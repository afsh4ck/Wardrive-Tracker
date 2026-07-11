"""
High-level PCAP analysis: turn a capture into geolocated WiFi networks and
Bluetooth devices.

Pipeline:
  raw record  ->  (PPI | radiotap | raw 802.11 | BLE) decode  ->
  extract {bssid/addr, ssid/name, channel, crypto, signal, gps}  ->
  aggregate per device with all sightings and a best (strongest-signal) fix.

WiFi is read from 802.11 beacon / probe-response management frames.
Bluetooth is read from BLE advertising frames (ADV_IND etc.).
Geolocation comes from PPI-GPS tags (Kismet/airodump with GPS) or, when
absent, is left empty (the device still appears in the inventory).
"""

import logging
import math

from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap

from . import ppi
from .oui import lookup_vendor

logging.getLogger("scapy").setLevel(logging.ERROR)

# BLE advertising is optional depending on scapy build; import defensively.
try:
    from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV
    from scapy.layers.bluetooth import (
        EIR_Hdr,
        EIR_CompleteLocalName,
        EIR_ShortenedLocalName,
    )
    _HAS_BTLE = True
except Exception:  # pragma: no cover - depends on scapy build
    _HAS_BTLE = False


class Sighting:
    """One observation of a device, optionally with a GPS fix."""

    __slots__ = ("ts", "signal", "lat", "lon", "channel", "accuracy")

    def __init__(self, ts, signal, lat, lon, channel, accuracy=None):
        self.ts = ts
        self.signal = signal
        self.lat = lat
        self.lon = lon
        self.channel = channel
        self.accuracy = accuracy   # GPS horizontal accuracy in metres, if known


def _uncertainty_m(best_signal, sightings):
    """Radio de incertidumbre (m) de la posición estimada de un emisor.

    Un fix de wardriving es la posición del *escáner*, no la del emisor: sitúa el
    dispositivo en el punto del recorrido donde se pasó más cerca, no en el
    edificio real. Este radio comunica esa incertidumbre de forma honesta.

    - Con señal: se deriva del RSSI más fuerte por el modelo log-distancia de
      pérdida de propagación (ref -40 dBm, exponente 3) -> distancia aproximada
      del paso más cercano al emisor.
    - Sin señal: dispersión espacial de los avistamientos respecto al centroide.

    Se aplica un suelo por la precisión GPS reportada, con mínimo 10 m y tope 300 m.
    """
    acc = [s.accuracy for s in sightings if s.accuracy]
    floor = max(acc) if acc else 10.0
    if best_signal is not None:
        r = 10.0 ** ((-40.0 - best_signal) / 30.0)
    elif len(sightings) >= 2:
        clat = sum(s.lat for s in sightings) / len(sightings)
        clon = sum(s.lon for s in sightings) / len(sightings)
        mlat = 111320.0
        mlon = 111320.0 * math.cos(math.radians(clat))
        r = math.sqrt(sum(((s.lon - clon) * mlon) ** 2 + ((s.lat - clat) * mlat) ** 2
                          for s in sightings) / len(sightings))
    else:
        r = floor
    return round(min(max(r, floor, 10.0), 300.0), 1)


class Device:
    """Aggregated record for a WiFi AP or a Bluetooth device."""

    def __init__(self, kind, addr):
        self.kind = kind  # "wifi" | "bluetooth"
        self.addr = addr
        self.name = None            # SSID or BLE local name
        self.channel = None
        self.encryption = None      # wifi only
        self.device_type = None     # bluetooth only
        self.vendor = lookup_vendor(addr)
        self.first_seen = None
        self.last_seen = None
        self.packets = 0
        self.best_signal = None
        self.sightings = []

    def add(self, ts, signal, lat, lon, channel, accuracy=None):
        self.packets += 1
        if ts is not None:
            self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
            self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)
        if signal is not None and (self.best_signal is None or signal > self.best_signal):
            self.best_signal = signal
        if channel is not None:
            self.channel = channel
        if lat is not None and lon is not None:
            self.sightings.append(Sighting(ts, signal, lat, lon, channel, accuracy))

    def location(self):
        """
        Best position estimate with an uncertainty radius (``radius_m``).

        When signal is available we take the **RSSI-weighted centroid**: each
        sighting is weighted by its linear power (``10**(dBm/10)``), so the
        strongest (closest) passes dominate and pull the estimate toward the
        nearest-approach point instead of trusting a single, possibly noisy,
        strongest sample. With no signal we fall back to a plain centroid.

        The estimate is still constrained to *where the scanner drove*; the true
        emitter can be up to ``radius_m`` away (use geowifi to place it on its
        actual building). See :func:`_uncertainty_m`.
        """
        located = [s for s in self.sightings if s.lat is not None]
        if not located:
            return None
        with_sig = [s for s in located if s.signal is not None]
        if with_sig:
            weights = [10.0 ** (s.signal / 10.0) for s in with_sig]
            wsum = sum(weights) or 1.0
            lat = sum(w * s.lat for w, s in zip(weights, with_sig)) / wsum
            lon = sum(w * s.lon for w, s in zip(weights, with_sig)) / wsum
            best = max(s.signal for s in with_sig)
            source = "weighted-centroid" if len(with_sig) > 1 else "best-signal"
            return {"lat": lat, "lon": lon, "source": source,
                    "radius_m": _uncertainty_m(best, located)}
        lat = sum(s.lat for s in located) / len(located)
        lon = sum(s.lon for s in located) / len(located)
        return {"lat": lat, "lon": lon, "source": "centroid",
                "radius_m": _uncertainty_m(None, located)}

    def to_dict(self):
        loc = self.location()
        track = [
            {"lat": s.lat, "lon": s.lon, "signal": s.signal, "ts": s.ts}
            for s in self.sightings if s.lat is not None
        ]
        d = {
            "kind": self.kind,
            "addr": self.addr,
            "name": self.name,
            "vendor": self.vendor,
            "channel": self.channel,
            "packets": self.packets,
            "best_signal": self.best_signal,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "location": loc,
            "sightings": track,
        }
        if self.kind == "wifi":
            d["encryption"] = self.encryption
        else:
            d["device_type"] = self.device_type
        return d


def _channel_from_freq(freq):
    if not freq:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    return None


def _dot11_crypto(pkt):
    """Determine the encryption/authentication of a beacon/probe-response."""
    cap = ""
    try:
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                          "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
    except Exception:
        cap = ""
    privacy = "privacy" in cap

    has_rsn = False       # RSN IE (WPA2/WPA3)
    has_wpa = False       # vendor WPA IE (WPA1)
    sae = False           # WPA3-SAE AKM
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 48:  # RSN
            has_rsn = True
            info = bytes(elt.info)
            # AKM suite 8 == SAE (WPA3). Scan the AKM suite list for 00-0F-AC-08.
            if b"\x00\x0f\xac\x08" in info:
                sae = True
        elif elt.ID == 221 and bytes(elt.info)[:4] == b"\x00\x50\xf2\x01":
            has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt)

    if has_rsn and sae:
        return "WPA3"
    if has_rsn:
        return "WPA2"
    if has_wpa:
        return "WPA"
    if privacy:
        return "WEP"
    return "Open"


def _ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            try:
                raw = bytes(elt.info)
            except Exception:
                return None
            if not raw or all(b == 0 for b in raw):
                return "<hidden>"
            try:
                return raw.decode("utf-8", "replace")
            except Exception:
                return raw.hex()
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def _dot11_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 3 and len(bytes(elt.info)) >= 1:
            return bytes(elt.info)[0]
        elt = elt.payload.getlayer(Dot11Elt)
    return None


class PcapAnalyzer:
    def __init__(self):
        self.wifi = {}       # bssid -> Device
        self.bluetooth = {}  # addr -> Device
        self.packet_count = 0
        self.gps_points = 0
        self.linktypes = set()

    # -- per-frame handlers -------------------------------------------------

    def _handle_dot11(self, frame_bytes, ts, signal, gps, channel_hint):
        try:
            pkt = frame_bytes if isinstance(frame_bytes, Dot11) else Dot11(frame_bytes)
        except Exception:
            return
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return
        bssid = pkt.addr3 or pkt.addr2
        if not bssid:
            return
        bssid = bssid.lower()
        dev = self.wifi.get(bssid)
        if dev is None:
            dev = Device("wifi", bssid)
            self.wifi[bssid] = dev
        ssid = _ssid(pkt)
        if ssid and (dev.name is None or dev.name == "<hidden>"):
            dev.name = ssid
        dev.encryption = _dot11_crypto(pkt)
        channel = _dot11_channel(pkt) or channel_hint
        lat = gps["lat"] if gps else None
        lon = gps["lon"] if gps else None
        dev.add(ts, signal, lat, lon, channel)

    def _handle_btle(self, frame_bytes, ts, signal, gps):
        if not _HAS_BTLE:
            return
        try:
            pkt = BTLE(frame_bytes)
        except Exception:
            return
        adv = pkt.getlayer(BTLE_ADV)
        if adv is None:
            return
        addr = getattr(adv, "AdvA", None)
        if not addr:
            return
        addr = str(addr).lower()
        dev = self.bluetooth.get(addr)
        if dev is None:
            dev = Device("bluetooth", addr)
            self.bluetooth[addr] = dev
        name = _btle_name(pkt)
        if name and dev.name is None:
            dev.name = name
        if dev.device_type is None:
            dev.device_type = pkt.getlayer(BTLE_ADV).sprintf("%BTLE_ADV.PDU_type%")
        lat = gps["lat"] if gps else None
        lon = gps["lon"] if gps else None
        dev.add(ts, signal, lat, lon, None)

    def _dispatch_inner(self, dlt, inner, ts, signal, gps, channel_hint):
        if dlt in (ppi.LINKTYPE_IEEE802_11, ppi.LINKTYPE_IEEE802_11_RADIOTAP):
            if dlt == ppi.LINKTYPE_IEEE802_11_RADIOTAP:
                try:
                    rt = RadioTap(inner)
                    if signal is None:
                        signal = getattr(rt, "dBm_AntSignal", None)
                    inner = bytes(rt.payload)
                except Exception:
                    pass
            self._handle_dot11(inner, ts, signal, gps, channel_hint)
        elif dlt in (ppi.LINKTYPE_BLUETOOTH_LE_LL,
                     ppi.LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR):
            if dlt == ppi.LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
                inner = inner[10:]  # skip Nordic BLE pseudo-header
            self._handle_btle(inner, ts, signal, gps)

    # -- capture readers ----------------------------------------------------

    def _process_classic(self, path):
        for linktype, ts, data in ppi.read_classic_pcap(path):
            self.packet_count += 1
            self.linktypes.add(linktype)
            if linktype == ppi.LINKTYPE_PPI:
                gps, signal, freq, dlt, inner = ppi.parse_ppi(data)
                if gps:
                    self.gps_points += 1
                self._dispatch_inner(dlt, inner, ts, signal, gps,
                                     _channel_from_freq(freq))
            elif linktype == ppi.LINKTYPE_IEEE802_11_RADIOTAP:
                self._dispatch_inner(linktype, data, ts, None, None, None)
            elif linktype == ppi.LINKTYPE_IEEE802_11:
                self._handle_dot11(data, ts, None, None, None)
            elif linktype in (ppi.LINKTYPE_BLUETOOTH_LE_LL,
                              ppi.LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR):
                self._dispatch_inner(linktype, data, ts, None, None, None)

    def _process_pcapng(self, path):
        # Fallback for pcapng: let scapy iterate; only radiotap/raw 802.11 and
        # BLE without embedded GPS are supported here.
        from scapy.all import PcapNgReader
        with PcapNgReader(path) as reader:
            for pkt in reader:
                self.packet_count += 1
                ts = float(pkt.time) if getattr(pkt, "time", None) else None
                if pkt.haslayer(Dot11):
                    signal = getattr(pkt, "dBm_AntSignal", None)
                    self._handle_dot11(pkt.getlayer(Dot11), ts, signal, None, None)
                elif _HAS_BTLE and pkt.haslayer(BTLE):
                    self._handle_btle(bytes(pkt.getlayer(BTLE)), ts, None, None)

    # -- entry point --------------------------------------------------------

    def analyze(self, path):
        if ppi.is_pcapng(path):
            self._process_pcapng(path)
        else:
            self._process_classic(path)
        return self.result(path)

    def result(self, path):
        import os

        wifi = [d.to_dict() for d in self.wifi.values()]
        bt = [d.to_dict() for d in self.bluetooth.values()]

        coords = []
        for d in wifi + bt:
            if d["location"]:
                coords.append((d["location"]["lat"], d["location"]["lon"]))
        bounds = None
        if coords:
            lats = [c[0] for c in coords]
            lons = [c[1] for c in coords]
            bounds = {"min_lat": min(lats), "max_lat": max(lats),
                      "min_lon": min(lons), "max_lon": max(lons)}

        return {
            "meta": {
                "filename": os.path.basename(path),
                "packet_count": self.packet_count,
                "linktypes": sorted(self.linktypes),
                "wifi_count": len(wifi),
                "bluetooth_count": len(bt),
                "gps_points": self.gps_points,
                "located_count": len(coords),
                "has_gps": len(coords) > 0,
                "bounds": bounds,
            },
            "wifi": wifi,
            "bluetooth": bt,
        }


def _btle_name(pkt):
    """
    Extract a BLE local name. The advertising payload is a *list* field
    (``data=[EIR_Hdr()/..., ...]``) on the ADV PDU layer, not a payload chain,
    so we walk the layers looking for a ``data`` list of EIR structures.
    """
    if not _HAS_BTLE:
        return None
    layer = pkt
    while layer is not None:
        entries = getattr(layer, "data", None)
        if isinstance(entries, list):
            for eir in entries:
                for cls in (EIR_CompleteLocalName, EIR_ShortenedLocalName):
                    if eir.haslayer(cls):
                        try:
                            raw = bytes(eir.getlayer(cls).local_name)
                            return raw.decode("utf-8", "replace")
                        except Exception:
                            pass
        layer = layer.payload if layer.payload else None
    return None


def analyze_pcap(path):
    """Convenience wrapper: analyze a capture file and return the result dict."""
    return PcapAnalyzer().analyze(path)
