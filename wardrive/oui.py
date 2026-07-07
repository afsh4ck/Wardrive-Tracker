"""
Minimal built-in OUI (first 3 bytes of a MAC) -> vendor lookup.

This is a small curated subset for common consumer/network gear so the UI can
show a manufacturer without a multi-megabyte IEEE database. Unknown prefixes
return None. A locally-administered address (bit 1 of the first octet set) is
reported as "Randomized/Local" since many phones and BLE devices rotate MACs.
"""

_OUI = {
    "001a11": "Google",
    "3c5ab4": "Google",
    "f4f5e8": "Google",
    "d85d4c": "TP-Link",
    "50c7bf": "TP-Link",
    "b0487a": "TP-Link",
    "001d0f": "TP-Link",
    "e894f6": "TP-Link",
    "c46e1f": "TP-Link",
    "a0f3c1": "TP-Link",
    "001c df": "Belkin",
    "ec1a59": "Belkin",
    "b4750e": "Belkin",
    "0018e7": "Cameo/Netgear",
    "00095b": "Netgear",
    "2c3033": "Netgear",
    "a040a0": "Netgear",
    "9c3dcf": "Netgear",
    "001132": "Synology",
    "0011d8": "Asustek",
    "2c56dc": "Asustek",
    "04d9f5": "Asustek",
    "1c872c": "Asustek",
    "38d547": "Asustek",
    "0013d4": "Asustek",
    "001e2a": "Netgear",
    "000c43": "Ralink/Mediatek",
    "00259c": "Cisco-Linksys",
    "001839": "Cisco-Linksys",
    "58bfea": "Cisco",
    "00000c": "Cisco",
    "0025b3": "HP",
    "3822d6": "Huawei",
    "48ad08": "Huawei",
    "e0247f": "Huawei",
    "80fb06": "Huawei",
    "001e10": "Huawei",
    "f8e811": "Ubiquiti",
    "24a43c": "Ubiquiti",
    "788a20": "Ubiquiti",
    "fcecda": "Ubiquiti",
    "0418d6": "Ubiquiti",
    "60022d": "Amazon",
    "44650d": "Amazon",
    "fc65de": "Amazon",
    "68544c": "Amazon",
    "34d270": "Amazon",
    "ac63be": "Amazon",
    "b47c9c": "Amazon",
    "acbc32": "Apple",
    "3c0754": "Apple",
    "f0dbf8": "Apple",
    "a4d1d2": "Apple",
    "d0817a": "Apple",
    "5c95ae": "Apple",
    "78ca39": "Apple",
    "88665a": "Apple",
    "b8098a": "Apple",
    "f0989d": "Apple",
    "001124": "Apple",
    "0026bb": "Apple",
    "8c8590": "Apple",
    "3451c9": "Apple",
    "d4909c": "Apple",
    "40b395": "Apple",
    "e0acf1": "Samsung",
    "5001bb": "Samsung",
    "1c62b8": "Samsung",
    "b407f9": "Samsung",
    "384b76": "Samsung",
    "0021d1": "Samsung",
    "8425db": "Samsung",
    "34145f": "Samsung",
    "cc07ab": "Samsung",
    "d0176a": "Samsung",
    "5cf370": "Xiaomi",
    "640980": "Xiaomi",
    "f8a45f": "Xiaomi",
    "286c07": "Xiaomi",
    "fc64ba": "Xiaomi",
    "74c14f": "Sonos",
    "5cae8b": "Sonos",
    "94d971": "Sonos",
    "b8e937": "Sonos",
    "001788": "Philips Hue",
    "ecb5fa": "Philips Hue",
    "0017880": "Philips Hue",
    "00055d": "D-Link",
    "1cbdb9": "D-Link",
    "340804": "D-Link",
    "c8d3a3": "D-Link",
    "001cf0": "D-Link",
    "b8a386": "D-Link",
    "0080c8": "D-Link",
    "0024b2": "Netgear",
    "e4956e": "IEEE Registration (private)",
}


def lookup_vendor(mac):
    if not mac:
        return None
    hexmac = mac.replace(":", "").replace("-", "").lower()
    if len(hexmac) < 6:
        return None
    # locally administered (random) address?
    try:
        first_octet = int(hexmac[:2], 16)
        if first_octet & 0x02:
            return "Randomized/Local"
    except ValueError:
        return None
    return _OUI.get(hexmac[:6])
