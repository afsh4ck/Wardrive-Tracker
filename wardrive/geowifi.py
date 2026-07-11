"""
Geolocalización de BSSIDs por bases de datos WiFi públicas (técnica de geowifi).

Cuando una captura NO trae etiquetas PPI-GPS, las redes aparecen en el inventario
pero sin posición. Este módulo consulta la ubicación de un BSSID en servicios
públicos, igual que https://github.com/GONZOsint/geowifi , para poder situarlas en
el mapa. Las coordenadas NO son un fix GPS de la captura: son datos OSINT de bases
de terceros (Apple), con la precisión y latencia de actualización de esas bases.

Dos rutas:
  - **Nativa (por defecto)**: puerto en Python puro del módulo *apple* de geowifi.
    Consulta el servicio de localización de Apple (gs-loc.apple.com), que no
    requiere API key. Una consulta devuelve el BSSID pedido y ~100 vecinos, que
    se cachean para resolver otros BSSIDs de la captura sin más peticiones.
  - **CLI (opcional)**: si defines la variable de entorno ``GEOWIFI_DIR`` apuntando
    a un clon de geowifi, se delega en ``geowifi.py -s bssid <bssid> -o json`` para
    aprovechar TODAS sus fuentes (Wigle, Google, Combain, WifiDB…) con tus API keys.

Sin dependencias nuevas: solo stdlib (urllib) y un mini-decoder protobuf propio,
en línea con la convención del proyecto de lector pcap/PPI en Python puro.
"""

import os
import struct
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from .oui import lookup_vendor

APPLE_URL = "https://gs-loc.apple.com/clls/wloc"

# Cabeceras y prefijo binario tal cual los usa el módulo apple de geowifi /
# iSniff-GPS. El prefijo declara locale, bundle id de locationd y versión.
_APPLE_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "User-Agent": "locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0",
}
_APPLE_PREFIX = (
    b"\x00\x01\x00\x05en_US\x00\x13com.apple.locationd"
    b"\x00\x0a8.1.12B411\x00\x00\x00\x01\x00\x00\x00"
)

# Apple usa este valor (grados * 1e8) para "sin datos".
_APPLE_NODATA = -18000000000


# --------------------------------------------------------------------------
# Utilidades de MAC
# --------------------------------------------------------------------------

def _norm_mac(mac):
    """Normaliza a ``aa:bb:cc:dd:ee:ff`` en minúsculas y con ceros a la izquierda.

    Apple devuelve los octetos sin rellenar (p.ej. ``1a:2b:3:4d:5:6f``); esto los
    deja comparables con las claves de agregación de la captura (siempre minúsculas
    con dos dígitos por octeto).
    """
    if not mac:
        return mac
    parts = str(mac).lower().replace("-", ":").split(":")
    if len(parts) != 6:
        return str(mac).lower()
    try:
        return ":".join("%02x" % int(p, 16) for p in parts)
    except ValueError:
        return str(mac).lower()


# --------------------------------------------------------------------------
# Mini-decoder protobuf (solo lo necesario para la respuesta de Apple)
# --------------------------------------------------------------------------

def _read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _iter_fields(buf):
    """Itera (field_number, wire_type, value) de un mensaje protobuf.

    value es un int para varints (wire 0) y bytes para length-delimited (wire 2).
    Los tipos fijos 32/64 se saltan; los grupos (deprecados) cortan el parseo.
    """
    pos = 0
    n = len(buf)
    while pos < n:
        try:
            tag, pos = _read_varint(buf, pos)
            field = tag >> 3
            wire = tag & 0x07
            if wire == 0:
                val, pos = _read_varint(buf, pos)
                yield field, val
            elif wire == 2:
                length, pos = _read_varint(buf, pos)
                val = buf[pos:pos + length]
                pos += length
                yield field, val
            elif wire == 5:
                pos += 4
            elif wire == 1:
                pos += 8
            else:
                return
        except IndexError:
            return


def _signed64(v):
    """Interpreta un varint como int64 con signo (complemento a dos)."""
    if v >= (1 << 63):
        v -= (1 << 64)
    return v


def _parse_location(buf):
    """Location: lat=1, lon=2, precisión horizontal=3 (todos varint, grados*1e8)."""
    lat = lon = acc = None
    for field, val in _iter_fields(buf):
        if isinstance(val, int):
            if field == 1:
                lat = _signed64(val)
            elif field == 2:
                lon = _signed64(val)
            elif field == 3:
                acc = _signed64(val)
    if lat is None or lon is None or lat == _APPLE_NODATA or lon == _APPLE_NODATA:
        return None
    latf = lat / 1e8
    lonf = lon / 1e8
    if not (-90.0 <= latf <= 90.0 and -180.0 <= lonf <= 180.0):
        return None
    return latf, lonf, (int(acc) if acc is not None and acc >= 0 else None)


def _parse_response(raw):
    """Devuelve {mac_normalizada: (lat, lon, precisión)} de la respuesta de Apple."""
    out = {}
    if len(raw) <= 10:
        return out
    body = raw[10:]  # saltar cabecera de 10 bytes
    for field, val in _iter_fields(body):
        # BSSIDResp.wifi = campo 2, repetido, length-delimited.
        if field == 2 and isinstance(val, (bytes, bytearray)):
            mac = None
            loc = None
            for f2, v2 in _iter_fields(val):
                if f2 == 1 and isinstance(v2, (bytes, bytearray)):
                    mac = v2.decode("ascii", "replace")
                elif f2 == 2 and isinstance(v2, (bytes, bytearray)):
                    loc = _parse_location(v2)
            if mac and loc:
                out[_norm_mac(mac)] = loc
    return out


# --------------------------------------------------------------------------
# Consulta nativa a Apple
# --------------------------------------------------------------------------

def _build_apple_request(mac):
    mac_b = mac.encode("ascii")
    sub = b"\x0a" + struct.pack("B", len(mac_b)) + mac_b        # BSSID.bssid = 1
    bssid_field = b"\x12" + struct.pack("B", len(sub)) + sub + b"\x18\x00\x20\x01"
    return _APPLE_PREFIX + struct.pack("B", len(bssid_field)) + bssid_field


def _apple_query(mac, timeout):
    body = _build_apple_request(mac)
    req = urllib.request.Request(APPLE_URL, data=body, headers=_APPLE_HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return _parse_response(raw)


# --------------------------------------------------------------------------
# Delegación opcional en un geowifi instalado (GEOWIFI_DIR)
# --------------------------------------------------------------------------

def _cli_query(geowifi_dir, mac, timeout):
    """Ejecuta geowifi.py y extrae (lat, lon, módulo) de su salida JSON."""
    import json
    import subprocess
    import sys

    script = os.path.join(geowifi_dir, "geowifi.py")
    if not os.path.isfile(script):
        raise RuntimeError("No se encontró geowifi.py en GEOWIFI_DIR=%s" % geowifi_dir)
    proc = subprocess.run(
        [sys.executable, script, "-s", "bssid", mac, "-o", "json"],
        cwd=geowifi_dir, capture_output=True, text=True, timeout=timeout,
    )
    text = proc.stdout or ""
    start = text.find("[")
    if start == -1:
        return {}
    try:
        entries = json.loads(text[start:text.rfind("]") + 1])
    except ValueError:
        return {}
    out = {}
    for e in entries if isinstance(entries, list) else []:
        lat = e.get("latitude")
        lon = e.get("longitude")
        bssid = e.get("bssid")
        if lat in (None, "") or lon in (None, "") or not bssid:
            continue
        try:
            out[_norm_mac(bssid)] = (float(lat), float(lon), e.get("module"))
        except (TypeError, ValueError):
            continue
    return out


# --------------------------------------------------------------------------
# API pública
# --------------------------------------------------------------------------

def _entry_from_hit(hit, provider):
    lat, lon, extra = hit
    entry = {"lat": lat, "lon": lon, "module": "apple", "accuracy": None}
    if provider == "geowifi-cli":
        entry["module"] = extra
    elif isinstance(extra, int):
        entry["accuracy"] = extra
    return entry


def _default_workers():
    """Nº de hilos concurrentes para las consultas (env GEOWIFI_WORKERS, 1..32)."""
    try:
        n = int(os.environ.get("GEOWIFI_WORKERS", "10"))
    except ValueError:
        n = 10
    return max(1, min(32, n))


def iter_locate_bssids(bssids, timeout=6.0, max_queries=None, workers=None):
    """Geolocaliza BSSIDs **en paralelo** emitiendo progreso incremental (generador).

    Procesa la lista por lotes; dentro de cada lote lanza hasta ``workers``
    consultas concurrentes a Apple (el cuello de botella es la latencia de red,
    no la CPU, así que los hilos escalan bien). El **caché de vecinos** se conserva
    ENTRE lotes: una consulta devuelve ~100 BSSIDs cercanos, así que los lotes
    siguientes resuelven muchos sin consulta propia. Por cada lote —y al final—
    produce un dict::

        {"done", "total", "found", "queried", "provider",
         "located": {bssid: {...}},  # SOLO los nuevos desde el último evento
         "errors": [...], "aborted": bool}

    Salta MACs aleatorias/locales. Corta pronto si el servicio parece caído
    (2 lotes seguidos con todas las consultas fallando y ningún resultado).
    """
    geowifi_dir = os.environ.get("GEOWIFI_DIR")
    provider = "geowifi-cli" if geowifi_dir else "apple"
    if max_queries is None:
        max_queries = len(bssids)
    if workers is None:
        workers = _default_workers()
    chunk = max(workers * 4, 20)   # varias "olas" de paralelismo por lote
    total = len(bssids)

    def query_one(norm):
        if geowifi_dir:
            return _cli_query(geowifi_dir, norm, timeout)
        return _apple_query(norm, timeout)

    cache = {}          # mac_normalizada -> (lat, lon, acc/module) | None
    errors = []
    queried = 0
    found_total = 0
    consec_error_batches = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, total, chunk):
            batch = bssids[start:start + chunk]

            # BSSIDs del lote que necesitan consulta: no aleatorios, no cacheados,
            # dedup por MAC normalizada, respetando el tope de consultas.
            to_query = {}   # norm -> raw
            for raw in batch:
                if lookup_vendor(raw) == "Randomized/Local":
                    continue
                norm = _norm_mac(raw)
                if norm in cache or norm in to_query:
                    continue
                if queried + len(to_query) >= max_queries:
                    break
                to_query[norm] = raw

            # Lanzar las consultas del lote en paralelo.
            batch_errors = 0
            if to_query:
                futures = {pool.submit(query_one, norm): norm for norm in to_query}
                for fut in as_completed(futures):
                    norm = futures[fut]
                    queried += 1
                    try:
                        found = fut.result()
                        for mac, tup in found.items():
                            cache[mac] = tup
                        cache.setdefault(norm, None)
                    except Exception as exc:  # red caída, timeout, endpoint no disponible…
                        batch_errors += 1
                        errors.append("%s: %s" % (norm, exc))

            if to_query and batch_errors == len(to_query) and found_total == 0:
                consec_error_batches += 1
            else:
                consec_error_batches = 0

            # Resolver el lote desde el caché (incluye vecinos de lotes previos).
            pending = {}
            for raw in batch:
                hit = cache.get(_norm_mac(raw))
                if hit:
                    pending[raw] = _entry_from_hit(hit, provider)
                    found_total += 1

            done = min(start + chunk, total)
            aborted = consec_error_batches >= 2 and found_total == 0
            yield {"done": done, "total": total, "found": found_total,
                   "queried": queried, "provider": provider,
                   "located": pending, "errors": errors[-3:], "aborted": aborted}
            if aborted:
                return
            pending = {}


def locate_bssids(bssids, timeout=8.0, max_queries=80):
    """Geolocaliza una lista de BSSIDs (versión de una tacada, sin streaming).

    Devuelve::

        {
          "located": {bssid: {"lat", "lon", "accuracy", "module"}},
          "queried": int,   # peticiones de red realizadas
          "found":   int,   # BSSIDs resueltos
          "provider": "apple" | "geowifi-cli",
          "errors":  [str, ...],
        }

    Se apoya en :func:`iter_locate_bssids`; para grandes volúmenes con progreso,
    usa el generador directamente (lo hace el endpoint ``/api/geolocate_stream``).
    """
    located = {}
    last = {}
    for ev in iter_locate_bssids(bssids, timeout=timeout, max_queries=max_queries):
        located.update(ev.get("located") or {})
        last = ev
    return {
        "located": located,
        "queried": last.get("queried", 0),
        "found": len(located),
        "provider": last.get("provider", "apple"),
        "errors": last.get("errors", []),
    }
