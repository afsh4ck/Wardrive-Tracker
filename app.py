"""
wardrive_tracker web app.

Upload a PCAP; the backend parses WiFi networks and Bluetooth devices, then the
frontend plots everything with a GPS fix on a Leaflet map and lets you inspect
each network/device.

Run:  python app.py   ->   http://127.0.0.1:5000
"""

import os
import tempfile
import traceback

from flask import Flask, jsonify, render_template, request

from wardrive import geowifi
from wardrive.parser import analyze_pcap
from wardrive.ppi import PcapFormatError
from wardrive.wigle import analyze_wigle, looks_like_wigle

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB cap

PCAP_EXT = {".pcap", ".pcapng", ".cap"}
WIGLE_EXT = {".log", ".csv", ".txt"}
ALLOWED_EXT = PCAP_EXT | WIGLE_EXT


def _is_wigle_file(path):
    """Comprueba por contenido si un archivo es un log WigleWifi CSV."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return looks_like_wigle(fh.read(4096))
    except OSError:
        return False


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No se ha enviado ningún archivo."}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Nombre de archivo vacío."}), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"error": "Formato no soportado. Usa .pcap/.pcapng/.cap "
                                 "o un log wardrive .log/.csv/.txt (WigleWifi CSV)."}), 400

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    try:
        f.save(tmp.name)
        tmp.close()

        # Rutas de texto (.log/.csv/.txt) -> WigleWifi CSV; binarias -> PCAP.
        # Para .csv/.txt/.log confirmamos con una lectura de cabecera por si el
        # usuario pone la extensión equivocada.
        if ext in WIGLE_EXT or _is_wigle_file(tmp.name):
            result = analyze_wigle(tmp.name)
        else:
            result = analyze_pcap(tmp.name)
        result["meta"]["filename"] = f.filename
        return jsonify(result)
    except PcapFormatError as exc:
        return jsonify({"error": "El archivo no es un PCAP válido: %s" % exc}), 400
    except ValueError as exc:
        return jsonify({"error": "El log wardrive no es válido: %s" % exc}), 400
    except Exception as exc:  # pragma: no cover
        traceback.print_exc()
        return jsonify({"error": "Error al analizar el archivo: %s" % exc}), 500
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@app.route("/api/geolocate", methods=["POST"])
def geolocate():
    """Geolocaliza BSSIDs sin GPS consultando bases WiFi públicas (geowifi).

    Recibe {"bssids": ["aa:bb:.."]} y devuelve las coordenadas encontradas. Son
    datos OSINT de terceros, NO un fix GPS de la captura.
    """
    payload = request.get_json(silent=True) or {}
    bssids = payload.get("bssids")
    if not isinstance(bssids, list) or not bssids:
        return jsonify({"error": "No se han enviado BSSIDs."}), 400
    # Un lote grande por petición: el frontend trocea listas enormes (miles de
    # redes) en varias llamadas. `max_queries` == tamaño del lote para intentar
    # TODOS los BSSIDs del lote (el caché de vecinos de Apple evita repetir).
    bssids = [str(b).lower() for b in bssids if b][:500]
    try:
        return jsonify(geowifi.locate_bssids(bssids, max_queries=len(bssids)))
    except Exception as exc:  # pragma: no cover
        traceback.print_exc()
        return jsonify({"error": "Error en la geolocalización: %s" % exc}), 500


@app.route("/api/sample")
def sample():
    """Serve the bundled demo capture analysis, if present."""
    path = os.path.join(os.path.dirname(__file__), "sample_data", "wardrive_demo.pcap")
    if not os.path.exists(path):
        return jsonify({"error": "No hay captura de ejemplo. Genera una con "
                                 "'python tools/make_sample.py'."}), 404
    result = analyze_pcap(path)
    result["meta"]["filename"] = "wardrive_demo.pcap (ejemplo)"
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
