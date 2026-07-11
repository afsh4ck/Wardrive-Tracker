<div align="center">

# 📡 Wardrive Tracker

**Geolocaliza redes WiFi y dispositivos Bluetooth a partir de un PCAP o de un log
wardrive (WigleWifi CSV).**

<img width="2560" height="1238" alt="image" src="https://github.com/user-attachments/assets/6cc34e7c-afbb-4523-ab01-8aad69433266" />

Sube una captura **PCAP** o un **log WigleWifi CSV** (`.log`/`.csv`/`.txt`, p. ej.
ESP32 Marauder) → parseo de tramas 802.11 / BLE → mapa interactivo con panel de
detalles, cifrado, fabricante y traza de avistamientos. Sin GPS en la captura,
geolocaliza los BSSIDs por bases de datos WiFi públicas con la técnica de
[geowifi](https://github.com/GONZOsint/geowifi).

<p>
  <img alt="Python"  src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white">
  <img alt="Flask"   src="https://img.shields.io/badge/Flask-3-000000?logo=flask&logoColor=white">
  <img alt="scapy"   src="https://img.shields.io/badge/scapy-2.7-4B8BBE">
  <img alt="Leaflet" src="https://img.shields.io/badge/Leaflet-1.9-199900?logo=leaflet&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/uso-autorizado-important">
</p>

</div>

---

## Tabla de contenidos

- [Características](#-características)
- [¿Cómo funciona?](#-cómo-funciona)
- [El GPS y las capturas — importante](#️-el-gps-y-las-capturas--importante)
- [Geolocalización OSINT con geowifi](#-geolocalización-osint-de-bssids-con-geowifi)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [API](#-api)
- [Uso como librería](#-uso-como-librería)
- [Arquitectura](#-arquitectura)
- [Formatos y enlaces de capa](#-formatos-y-enlaces-de-capa-soportados)
- [Uso legal](#️-uso-legal)

---

## ✨ Características

- 🛜 **Redes WiFi** desde tramas *beacon* / *probe response* 802.11:
  BSSID, SSID (incluye ocultas), canal, fabricante (OUI), RSSI, nº de paquetes y
  primer/último visto.
- 📄 **Logs wardrive WigleWifi CSV** (`.log`/`.csv`/`.txt`): formato de exportación
  de **ESP32 Marauder**, Kismet, WiGLE… Traen **GPS en cada fila**, así que
  geolocalizan directamente sin necesidad de PPI-GPS ni geowifi.
- 🔐 **Detección de cifrado**: `Open` · `WEP` · `WPA` · `WPA2` · `WPA3`
  (por IE RSN y AKM SAE).
- 🔵 **Dispositivos Bluetooth LE** desde anuncios (`ADV_IND`, …):
  BD_ADDR, nombre local (EIR), tipo de PDU, fabricante y RSSI.
- 🗺️ **Mapa interactivo** (Leaflet, tema oscuro) con marcadores por tipo/cifrado,
  panel de detalles, traza de avistamientos y filtro en vivo.
- 📍 **GPS real** desde etiquetas **PPI-GPS** (Kismet / airodump con `gpsd`),
  ubicando cada dispositivo por su avistamiento de mayor señal.
- 🌍 **Geolocalización OSINT de BSSIDs sin GPS** con la técnica de **geowifi**
  (bases WiFi públicas), claramente diferenciada de un fix GPS.
- 🧩 **Pila mínima**: Flask + scapy en el backend, *vanilla* JS + Leaflet en el
  frontend. El lector de pcap clásico, el decoder PPI y el cliente de geowifi son
  **Python puro** (stdlib), sin dependencias extra.

---

## 🔎 ¿Cómo funciona?

```
PCAP  ─▶ lector de registros ─▶ decode por link-type ─▶ extrae campos ─┐
                                                                       ├─▶ agrega por dispositivo ─▶ JSON ─▶ mapa Leaflet
log CSV ─▶ WigleWifi CSV ─▶ fila = MAC/SSID/cifrado/RSSI/GPS ──────────┘
```

**PCAP:** cada trama se decodifica según su *link-type* (PPI, radiotap, 802.11
crudo o BLE LL), se extraen sus campos (BSSID/SSID/canal/cifrado/GPS o
BD_ADDR/nombre).

**Log WigleWifi CSV:** cada fila ya es un avistamiento con MAC, SSID, `AuthMode`
(→ cifrado), RSSI, canal, timestamp y **coordenadas GPS**.

En ambos casos se **agrega por dispositivo** acumulando todos sus avistamientos y
su mejor fix (el de mayor señal). La ruta de subida detecta el formato por la
extensión y por el contenido, así que da igual si el log llega como `.log`, `.csv`
o `.txt`.

---

## ⚠️ El GPS y las capturas — importante

> [!TIP]
> Esto solo afecta a los **PCAP**. Si subes un **log WigleWifi CSV**
> (`.log`/`.csv`/`.txt`), el GPS ya viene en cada fila y todo se sitúa en el mapa
> directamente, sin nada de lo de abajo.

Una captura PCAP WiFi/BT **normal no contiene coordenadas**. Para geolocalizar con
GPS real, la captura debe incluir etiquetas **PPI-GPS** (estándar
*PPI-GEOLOCATION*), que generan las herramientas de wardriving con fuente GPS:

| Herramienta      | Cómo                              |
| ---------------- | --------------------------------- |
| **Kismet**       | con GPS vía `gpsd` → pcap PPI-GPS  |
| **airodump-ng**  | con `gpsd` y salida PPI            |

Sin PPI-GPS, la app **lista igualmente** todas las redes y dispositivos
(inventario) y te avisa con un banner — pero no puede situarlos en el mapa… a menos
que uses la geolocalización OSINT ⤵️.

---

## 🌍 Geolocalización OSINT de BSSIDs con geowifi

¿Tu captura no trae GPS? Puedes situar las **redes WiFi** consultando su BSSID en
bases de datos públicas, aplicando la técnica de
[**geowifi**](https://github.com/GONZOsint/geowifi).

Tras cargar una captura, pulsa **Geolocalizar BSSIDs (geowifi)**. Por cada red sin
GPS se consulta el servicio de localización de **Apple** (`gs-loc.apple.com`, sin
API key); si el BSSID está en la base, se pinta en el mapa. Una sola consulta
devuelve el BSSID pedido **y sus vecinos**, que se cachean para resolver varios
BSSIDs con menos peticiones.

> [!IMPORTANT]
> Estas ubicaciones son **datos OSINT de un tercero, NO un fix GPS de tu captura**.
> Se muestran con un **marcador hueco a trazos** y un aviso en el panel de detalle
> para no confundirlas con las posiciones PPI-GPS.

- 🔒 Es una acción **explícita**: no se lanza al subir la captura, porque envía los
  BSSIDs capturados a Apple. Se omiten las MACs aleatorias/locales.
- 🧵 El parseo protobuf de la respuesta de Apple está implementado en **Python puro**
  (mini-parser propio), sin dependencia de `protobuf`.
- 🔑 ¿Quieres **todas** las fuentes de geowifi (Wigle, Google, Combain, WifiDB…)
  con tus propias API keys? Clona geowifi y exporta `GEOWIFI_DIR` antes de arrancar:

  ```bash
  export GEOWIFI_DIR=/ruta/al/geowifi   # la app delegará en su CLI (-o json)
  python app.py
  ```

---

## 📦 Instalación

Requiere **Python 3.11+**.

```bash
git clone https://github.com/afsh4ck/Wardrive-Tracker.git
cd wardrive_tracker
pip install -r requirements.txt
```

---

## 🚀 Uso

```bash
python app.py
# abre http://127.0.0.1:5000
```

1. Pulsa **Subir captura** (o arrastra el archivo sobre el mapa): PCAP
   (`.pcap`/`.pcapng`/`.cap`) o log WigleWifi CSV (`.log`/`.csv`/`.txt`).
2. Explora la lista lateral: pestañas **WiFi / Bluetooth** con filtro por nombre,
   MAC, cifrado o fabricante.
3. Haz clic en una red/dispositivo o en un marcador para ver sus detalles y traza.
4. ¿PCAP sin GPS? Pulsa **Geolocalizar BSSIDs (geowifi)** para situar las redes por
   OSINT. (Los logs WigleWifi ya traen GPS, así que no lo necesitan.)

### ¿No tienes una captura con GPS?

Genera una de ejemplo (redes WiFi + BLE con coordenadas simuladas alrededor de
Madrid) y ábrela con el botón **Cargar ejemplo**:

```bash
python tools/make_sample.py
```

---

## 🔌 API

| Método | Ruta             | Descripción                                                        |
| ------ | ---------------- | ------------------------------------------------------------------ |
| `GET`  | `/`              | Interfaz web.                                                      |
| `POST` | `/api/upload`    | Sube un PCAP o log WigleWifi CSV (`multipart/form-data`, campo `file`) → JSON análisis. |
| `GET`  | `/api/sample`    | Análisis de la captura de ejemplo, si existe.                      |
| `POST` | `/api/geolocate` | Geolocaliza BSSIDs por geowifi. Body: `{"bssids": ["aa:bb:.."]}`.  |

Respuesta de `/api/geolocate`:

```json
{
  "located": { "aa:bb:cc:dd:ee:ff": { "lat": 40.4, "lon": -3.7, "accuracy": 40, "module": "apple" } },
  "queried": 3,
  "found": 1,
  "provider": "apple",
  "errors": []
}
```

---

## 🐍 Uso como librería

```python
from wardrive.parser import analyze_pcap

result = analyze_pcap("captura.pcap")
print(result["meta"])              # resumen: contadores, bounds, has_gps…
for ap in result["wifi"]:          # redes WiFi
    print(ap["addr"], ap["name"], ap["encryption"], ap["location"])

# Logs WigleWifi CSV (ESP32 Marauder, Kismet, WiGLE…) — mismo dict de salida
from wardrive.wigle import analyze_wigle
result = analyze_wigle("wardrive.log")

# Geolocalización OSINT de BSSIDs (técnica de geowifi)
from wardrive.geowifi import locate_bssids
print(locate_bssids(["aa:bb:cc:dd:ee:ff"]))
```

---

## 🏗️ Arquitectura

```
wardrive_tracker/
├── app.py                  # Flask: / , /api/upload , /api/sample , /api/geolocate
├── wardrive/
│   ├── parser.py           # PcapAnalyzer: disección 802.11 + BLE y agregación
│   ├── wigle.py            # lector de logs WigleWifi CSV (.log/.csv/.txt) con GPS
│   ├── ppi.py              # lector pcap clásico (sin scapy) + decoder PPI-GPS
│   ├── geowifi.py          # geolocalización OSINT de BSSIDs (Apple / geowifi CLI)
│   └── oui.py              # lookup de fabricante por OUI
├── tools/make_sample.py    # generador de captura de ejemplo con GPS
├── templates/index.html    # interfaz (mapa Leaflet)
├── static/
│   ├── js/app.js           # estado, mapa, lista, filtro, panel de detalles
│   └── css/style.css       # tema oscuro
└── sample_data/            # captura de ejemplo generada (git-ignored)
```

**Dos rutas de lectura del PCAP:**

- **pcap clásico** (`ppi.read_classic_pcap`): ruta principal. Soporta PPI (con
  GPS), radiotap, 802.11 crudo y BLE LL. El GPS solo se lee aquí.
- **pcapng** (fallback vía scapy): radiotap / 802.11 y BLE **sin** GPS.

---

## 🧬 Formatos y enlaces de capa soportados

- **Entrada:** `.pcap`, `.pcapng`, `.cap` y logs **WigleWifi CSV** `.log`, `.csv`,
  `.txt` (hasta 200 MB).
- **Link-types (PCAP):** PPI (192), radiotap (127), 802.11 crudo (105), BLE LL
  (251/256).
- **GPS:** desde capturas **PPI clásicas** (PPI-GEOLOCATION, tipo 30002) o desde
  cualquier fila de un **log WigleWifi CSV**.

---

## ⚖️ Uso legal

Analiza únicamente capturas **propias** o para las que tengas **autorización
explícita** (pentest, laboratorio, CTF, investigación). El escaneo, la captura y la
geolocalización de redes de terceros pueden ser ilegales según tu jurisdicción. La
consulta OSINT de geowifi envía los BSSIDs a servicios de terceros: úsala con
conocimiento de causa.

<div align="center">
<sub>Hecho para wardriving responsable. Créditos de la técnica de geolocalización por BSSID a <a href="https://github.com/GONZOsint/geowifi">GONZOsint/geowifi</a>.</sub>
</div>
