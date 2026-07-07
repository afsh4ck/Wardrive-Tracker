"""
Low-level PCAP record reader and PPI (Per-Packet Information) header decoder.

Wardriving tools such as Kismet and airodump-ng (with a GPS source) embed
geolocation directly inside the capture using the PPI-GEOLOCATION spec:
each packet is prefixed with a PPI header containing a GPS tag (lat/lon/alt)
and an 802.11-Common tag (channel + signal). This module parses the classic
libpcap container and those PPI tags without depending on scapy, so we keep
full control over the fixed-point GPS decoding.

Real-world radiotap / pcapng captures are handled separately in parser.py via
scapy; here we only need the raw record stream and the PPI tags.
"""

import struct

# libpcap link-layer types we care about
LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_PPI = 192
LINKTYPE_BLUETOOTH_HCI_H4 = 187
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
LINKTYPE_BLUETOOTH_LE_LL = 251
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256

# PPI field types
PPI_80211_COMMON = 2
PPI_GPS = 30002  # PPI-GEOLOCATION GPS tag

# PPI-GPS "present" bit positions
GPS_BIT_FLAGS = 0
GPS_BIT_LAT = 1
GPS_BIT_LON = 2
GPS_BIT_ALT = 3
GPS_BIT_ALT_G = 4


class PcapFormatError(Exception):
    pass


def is_pcapng(path):
    """pcapng starts with the Section Header Block magic 0x0A0D0D0A."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    return head == b"\x0a\x0d\x0d\x0a"


def read_classic_pcap(path):
    """
    Generator over a classic libpcap file.

    Yields (linktype, timestamp_float, packet_bytes) per record.
    Raises PcapFormatError if the global header magic is unrecognised.
    """
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise PcapFormatError("file too short to be a pcap")
        magic = gh[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
            nano = magic == b"\xa1\xb2\x3c\x4d"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
            nano = magic == b"\x4d\x3c\xb2\xa1"
        else:
            raise PcapFormatError("not a classic pcap (bad magic %r)" % magic)

        linktype = struct.unpack(endian + "I", gh[20:24])[0]

        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", rec)
            data = fh.read(incl_len)
            if len(data) < incl_len:
                break
            ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            yield linktype, ts, data


def _fixed3_7(raw):
    """PPI fixed3_7: stored uint32, degrees = raw/1e7 - 180."""
    return raw / 1e7 - 180.0


def _fixed6_4(raw):
    """PPI fixed6_4: stored uint32, metres = raw/1e4 - 180000."""
    return raw / 1e4 - 180000.0


def parse_ppi_gps(tag):
    """
    Decode a PPI-GPS tag body (bytes after the field header) into a dict with
    lat/lon/alt when present. Returns None if the tag has no coordinates.
    """
    if len(tag) < 8:
        return None
    ver, _pad, _glen, present = struct.unpack("<BBHI", tag[:8])
    off = 8
    out = {}

    def take_u32():
        nonlocal off
        if off + 4 > len(tag):
            return None
        val = struct.unpack("<I", tag[off:off + 4])[0]
        off += 4
        return val

    if present & (1 << GPS_BIT_FLAGS):
        take_u32()
    if present & (1 << GPS_BIT_LAT):
        v = take_u32()
        if v is not None:
            out["lat"] = _fixed3_7(v)
    if present & (1 << GPS_BIT_LON):
        v = take_u32()
        if v is not None:
            out["lon"] = _fixed3_7(v)
    if present & (1 << GPS_BIT_ALT):
        v = take_u32()
        if v is not None:
            out["alt"] = _fixed6_4(v)

    if "lat" in out and "lon" in out:
        return out
    return None


def parse_ppi(raw):
    """
    Parse a PPI packet header.

    Returns (gps_dict_or_None, signal_dbm_or_None, channel_freq_or_None,
             inner_dlt, inner_bytes). inner_bytes is the encapsulated frame
             (e.g. an 802.11 frame) that follows the PPI header.
    """
    if len(raw) < 8:
        return None, None, None, None, b""
    _ver, _flags, pph_len, dlt = struct.unpack("<BBHI", raw[:8])
    if pph_len > len(raw) or pph_len < 8:
        return None, None, None, dlt, raw[8:]

    gps = None
    signal = None
    freq = None
    off = 8
    while off + 4 <= pph_len:
        ftype, flen = struct.unpack("<HH", raw[off:off + 4])
        body = raw[off + 4:off + 4 + flen]
        off += 4 + flen
        if ftype == PPI_GPS:
            gps = parse_ppi_gps(body)
        elif ftype == PPI_80211_COMMON and len(body) >= 20:
            freq = struct.unpack("<H", body[12:14])[0]
            sig = struct.unpack("<b", body[18:19])[0]
            signal = sig

    inner = raw[pph_len:]
    return gps, signal, freq, dlt, inner
