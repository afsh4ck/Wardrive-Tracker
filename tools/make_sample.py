"""
Generate a synthetic wardriving capture: a classic-libpcap file where each
frame is wrapped in a PPI header carrying a GPS fix (PPI-GEOLOCATION) plus an
802.11-Common tag (channel + signal). Contains both 802.11 beacons and BLE
advertisements so the whole pipeline (parse -> map -> details) can be tested
without real hardware.

Usage:  python -m tools.make_sample [output.pcap]
"""

import math
import struct
import sys

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RSNCipherSuite,
    AKMSuite,
    Dot11EltRSN,
)

try:
    from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND
    from scapy.layers.bluetooth import EIR_Hdr, EIR_CompleteLocalName, EIR_Flags
    HAS_BTLE = True
except Exception:
    HAS_BTLE = False

LINKTYPE_PPI = 192
LINKTYPE_IEEE802_11 = 105
LINKTYPE_BLUETOOTH_LE_LL = 251

PPI_80211_COMMON = 2
PPI_GPS = 30002

# ---- fake city map (around Madrid) ---------------------------------------
# Each AP/device has a "true" position; signal falls off with distance as we
# drive the route, so the strongest sighting lands near the true spot.

WIFI = [
    # (bssid, ssid, channel, crypto, lat, lon)
    ("acbc32:11:22:33", "MOVISTAR_A1B2", 6, "wpa2", 40.4168, -3.7038),
    ("d85d4c:aa:bb:cc", "vodafone2233", 11, "wpa2", 40.4180, -3.7020),
    ("f8e811:44:55:66", "Corp-Guest", 1, "wpa3", 40.4155, -3.7050),
    ("001122:77:88:99", "linksys", 6, "wep", 40.4190, -3.7010),
    ("60022d:12:34:56", "FreeWiFi_Cafe", 3, "open", 40.4160, -3.7065),
    ("e0acf1:ab:cd:ef", "AndroidAP_9f", 9, "wpa2", 40.4175, -3.7045),
    ("74c14f:0a:0b:0c", "Sonos-Living", 44, "open", 40.4185, -3.7035),
    ("ecb5fa:de:ad:be", "Hue-Bridge", 1, "wpa2", 40.4150, -3.7025),
]

BLE = [
    # (addr, name, lat, lon)
    ("f0:98:9d:01:02:03", "AirPods Pro", 40.4169, -3.7040),
    ("cc:07:ab:04:05:06", "Galaxy Watch5", 40.4172, -3.7052),
    ("b8:e9:37:07:08:09", "Sonos Roam", 40.4184, -3.7034),
    ("ec:b5:fa:0a:0b:0c", "Hue Lamp", 40.4151, -3.7026),
    ("60:02:2d:0d:0e:0f", "Echo Dot", 40.4161, -3.7064),
]

# Driving route (a loop through the neighbourhood)
ROUTE = [
    (40.4148, -3.7060), (40.4155, -3.7055), (40.4162, -3.7048),
    (40.4168, -3.7040), (40.4174, -3.7033), (40.4181, -3.7026),
    (40.4188, -3.7018), (40.4183, -3.7030), (40.4176, -3.7042),
    (40.4169, -3.7050), (40.4160, -3.7058), (40.4152, -3.7038),
]


def haversine_m(a_lat, a_lon, b_lat, b_lon):
    r = 6371000.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dphi = math.radians(b_lat - a_lat)
    dl = math.radians(b_lon - a_lon)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def signal_for_distance(dist_m):
    """Log-distance path loss -> dBm, clamped to a sane RSSI range."""
    if dist_m < 1:
        dist_m = 1
    rssi = -40 - 25 * math.log10(dist_m)
    return int(max(-95, min(-30, rssi)))


def ppi_gps_tag(lat, lon, alt=650.0):
    present = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3)  # flags, lat, lon, alt
    body = struct.pack("<I", 0)                                    # GPSFlags
    body += struct.pack("<I", int(round((lat + 180.0) * 1e7)))     # lat fixed3_7
    body += struct.pack("<I", int(round((lon + 180.0) * 1e7)))     # lon fixed3_7
    body += struct.pack("<I", int(round((alt + 180000.0) * 1e4)))  # alt fixed6_4
    geotag = struct.pack("<BBHI", 2, 0, 8 + len(body), present) + body
    return struct.pack("<HH", PPI_GPS, len(geotag)) + geotag


def ppi_80211_common(freq, signal):
    body = struct.pack("<Q", 0)              # TSF
    body += struct.pack("<H", 0)             # flags
    body += struct.pack("<H", 0)             # rate
    body += struct.pack("<H", freq)          # channel freq
    body += struct.pack("<H", 0)             # channel flags
    body += struct.pack("<BB", 0, 0)         # FHSS hopset/pattern
    body += struct.pack("<b", signal)        # dBm antsignal
    body += struct.pack("<b", -95)           # dBm antnoise
    return struct.pack("<HH", PPI_80211_COMMON, len(body)) + body


def channel_to_freq(ch):
    if ch == 14:
        return 2484
    if ch <= 14:
        return 2407 + ch * 5
    return 5000 + ch * 5


def wrap_ppi(inner_dlt, frame, lat, lon, freq, signal):
    tags = ppi_80211_common(freq, signal) + ppi_gps_tag(lat, lon)
    pph = struct.pack("<BBHI", 0, 0, 8 + len(tags), inner_dlt)
    return pph + tags + frame


def build_beacon(bssid, ssid, channel, crypto):
    mac = bssid  # scapy accepts short form? no -> expand
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    cap = "ESS+privacy" if crypto != "open" else "ESS"
    beacon = Dot11Beacon(cap=cap)
    frame = dot11 / beacon
    frame /= Dot11Elt(ID="SSID", info=ssid)
    frame /= Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    frame /= Dot11Elt(ID="DSset", info=bytes([channel]))
    if crypto in ("wpa2", "wpa3"):
        akm = 8 if crypto == "wpa3" else 2  # SAE vs PSK
        rsn = Dot11EltRSN(
            group_cipher_suite=RSNCipherSuite(cipher=4),
            pairwise_cipher_suites=[RSNCipherSuite(cipher=4)],
            akm_suites=[AKMSuite(suite=akm)],
        )
        frame /= rsn
    return bytes(frame)


def full_mac(short):
    """Expand 'acbc32:11:22:33' -> 'ac:bc:32:11:22:33'."""
    head, tail = short.split(":", 1)
    head_bytes = ":".join(head[i:i + 2] for i in range(0, 6, 2))
    return head_bytes + ":" + tail


def build_btle_adv(addr, name):
    pkt = (
        BTLE(access_addr=0x8E89BED6)
        / BTLE_ADV(RxAdd=0, TxAdd=1, PDU_type=0)
        / BTLE_ADV_IND(
            AdvA=addr,
            data=[
                EIR_Hdr() / EIR_Flags(flags=0x06),
                EIR_Hdr() / EIR_CompleteLocalName(local_name=name),
            ],
        )
    )
    return bytes(pkt)


def write_pcap(path, records):
    with open(path, "wb") as fh:
        # global header, microsecond, linktype PPI
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_PPI))
        ts = 1_700_000_000
        for i, data in enumerate(records):
            usec = (i * 137) % 1_000_000
            fh.write(struct.pack("<IIII", ts + i // 8, usec, len(data), len(data)))
            fh.write(data)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_data/wardrive_demo.pcap"
    import os
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    records = []
    for wp_lat, wp_lon in ROUTE:
        for bssid, ssid, ch, crypto, tlat, tlon in WIFI:
            dist = haversine_m(wp_lat, wp_lon, tlat, tlon)
            if dist > 350:
                continue
            frame = build_beacon(full_mac(bssid), ssid, ch, crypto)
            rec = wrap_ppi(LINKTYPE_IEEE802_11, frame, wp_lat, wp_lon,
                           channel_to_freq(ch), signal_for_distance(dist))
            records.append(rec)

        if HAS_BTLE:
            for addr, name, tlat, tlon in BLE:
                dist = haversine_m(wp_lat, wp_lon, tlat, tlon)
                if dist > 250:
                    continue
                frame = build_btle_adv(addr, name)
                rec = wrap_ppi(LINKTYPE_BLUETOOTH_LE_LL, frame, wp_lat, wp_lon,
                               2440, signal_for_distance(dist))
                records.append(rec)

    write_pcap(out, records)
    print("Wrote %d records to %s" % (len(records), out))
    print("  WiFi APs: %d   BLE devices: %d   route points: %d"
          % (len(WIFI), len(BLE) if HAS_BTLE else 0, len(ROUTE)))
    if not HAS_BTLE:
        print("  (BLE layers unavailable in this scapy build; WiFi only)")


if __name__ == "__main__":
    main()
