"""
Lector de logs **WigleWifi CSV** (Wigle / ESP32 Marauder, Kismet export...).

A diferencia de un PCAP, este formato es texto y **trae el GPS en cada fila**,
así que las redes/dispositivos se sitúan en el mapa directamente, sin necesidad
de etiquetas PPI-GPS ni de geowifi.

Formato (dos líneas de cabecera + filas CSV):

    WigleWifi-1.4,appRelease=...,model=ESP32 Marauder,...
    MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
    84:AA:9C:24:7A:43,FinchyLynchy,[WPA2_PSK],2026-07-11 07:14:14,11,-85,40.3554649,-3.7015150,596.40,4.50,WIFI
    e4:7a:2c:e3:fd:20,,[BLE],2026-07-11 07:14:15,0,-52,40.3554688,-3.7015400,595.70,4.50,BLE

Reutiliza `Device`/`Sighting` de parser.py y produce el MISMO dict que
`analyze_pcap` (meta + wifi[] + bluetooth[]).
"""

import csv
import os
import re
from datetime import datetime, timezone

from .parser import Device

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def looks_like_wigle(head):
    """¿El comienzo del archivo (str) parece un log WigleWifi CSV?"""
    h = head.lstrip()
    if h.upper().startswith("WIGLEWIFI"):
        return True
    # Cabecera CSV directa, sin la línea de preámbulo.
    return bool(re.search(r"(?im)^\s*MAC\s*,\s*SSID\s*,\s*AuthMode", head))


def _enc_from_authmode(authmode):
    """Traduce el campo AuthMode de Wigle a nuestra etiqueta de cifrado."""
    s = (authmode or "").upper()
    if "WPA3" in s:
        return "WPA3"
    if "WPA2" in s:
        return "WPA2"
    if "WPA" in s:
        return "WPA"
    if "WEP" in s:
        return "WEP"
    # OWE (Enhanced Open) y OPEN/vacío -> abierta.
    return "Open"


def _to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _to_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _parse_ts(v):
    """FirstSeen -> epoch (segundos). Acepta 'YYYY-MM-DD HH:MM:SS' o epoch."""
    if not v:
        return None
    v = v.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            dt = datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    # Algunos exports usan epoch (s o ms).
    n = _to_float(v)
    if n is None:
        return None
    return n / 1000.0 if n > 1e11 else n


def analyze_wigle(path):
    """Analiza un log WigleWifi CSV y devuelve el dict estándar de la app."""
    wifi = {}       # mac -> Device
    bluetooth = {}  # mac -> Device
    records = 0
    gps_points = 0
    model = None

    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        lines = fh.read().splitlines()

    # Descarta el preámbulo "WigleWifi-..." (y quédate con el modelo si aparece)
    # hasta la fila de cabecera CSV que empieza por "MAC,".
    idx = 0
    while idx < len(lines) and not lines[idx].strip().upper().startswith("MAC,"):
        m = re.search(r"model=([^,]+)", lines[idx])
        if m:
            model = m.group(1).strip()
        idx += 1
    if idx >= len(lines):
        raise ValueError("No se encontró la cabecera CSV de WigleWifi (MAC,SSID,AuthMode,...).")

    reader = csv.DictReader(lines[idx:])
    for row in reader:
        mac = (row.get("MAC") or "").strip().lower()
        if not _MAC_RE.match(mac):
            continue

        typ = (row.get("Type") or "WIFI").strip().upper()
        ssid = (row.get("SSID") or "").strip() or None
        rssi = _to_int(row.get("RSSI"))
        channel = _to_int(row.get("Channel")) or None
        ts = _parse_ts(row.get("FirstSeen"))
        lat = _to_float(row.get("CurrentLatitude"))
        lon = _to_float(row.get("CurrentLongitude"))
        acc = _to_float(row.get("AccuracyMeters"))
        if acc is not None and acc <= 0:
            acc = None
        if lat is None or lon is None or (lat == 0.0 and lon == 0.0) \
           or abs(lat) > 90 or abs(lon) > 180:
            lat = lon = None

        if typ == "WIFI":
            dev = wifi.get(mac)
            if dev is None:
                dev = Device("wifi", mac)
                wifi[mac] = dev
            if ssid and dev.name is None:
                dev.name = ssid
            dev.encryption = _enc_from_authmode(row.get("AuthMode"))
            dev.add(ts, rssi, lat, lon, channel, acc)
        elif typ in ("BLE", "BT"):
            dev = bluetooth.get(mac)
            if dev is None:
                dev = Device("bluetooth", mac)
                bluetooth[mac] = dev
            if ssid and dev.name is None:
                dev.name = ssid
            if dev.device_type is None:
                dev.device_type = "BLE" if typ == "BLE" else "BT Classic"
            dev.add(ts, rssi, lat, lon, None, acc)
        else:
            # Torres de telefonía (GSM/LTE/NR...) u otros: se ignoran.
            continue

        records += 1
        if lat is not None and lon is not None:
            gps_points += 1

    return _build_result(path, wifi, bluetooth, records, gps_points, model)


def _build_result(path, wifi, bluetooth, records, gps_points, model):
    wifi_list = [d.to_dict() for d in wifi.values()]
    bt_list = [d.to_dict() for d in bluetooth.values()]

    coords = []
    for d in wifi_list + bt_list:
        if d["location"]:
            coords.append((d["location"]["lat"], d["location"]["lon"]))
    bounds = None
    if coords:
        lats = [c[0] for c in coords]
        lons = [c[1] for c in coords]
        bounds = {"min_lat": min(lats), "max_lat": max(lats),
                  "min_lon": min(lons), "max_lon": max(lons)}

    linktype = "WigleWifi CSV" + (" · %s" % model if model else "")
    return {
        "meta": {
            "filename": os.path.basename(path),
            "packet_count": records,
            "linktypes": [linktype],
            "wifi_count": len(wifi_list),
            "bluetooth_count": len(bt_list),
            "gps_points": gps_points,
            "located_count": len(coords),
            "has_gps": len(coords) > 0,
            "bounds": bounds,
        },
        "wifi": wifi_list,
        "bluetooth": bt_list,
    }
