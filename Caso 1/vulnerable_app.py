"""
vulnerable_app.py
-----------------
Demo educativa: endpoint /fetch que hace SSR (Server-Side Request) a una URL
dada por el usuario, con un filtro "ingenuo" basado en regex sobre el STRING
de la URL. No resuelve DNS, no normaliza representaciones alternativas de IP.

Correr:
    pip install flask requests
    python vulnerable_app.py
Escucha en http://localhost:5000
"""

from flask import Flask, request, jsonify
import requests
import re

app = Flask(__name__)

# --- "Metadata interna" simulada: lo que un atacante quiere robar vía SSRF ---
@app.route("/internal/secret")
def secret():
    return jsonify({
        "flag": "FLAG{ssrf_internal_metadata_leak}",
        "note": "Este endpoint deberia ser accesible SOLO desde localhost / red interna"
    })


# --- Filtro ingenuo: bloquea por patrones de texto, no valida la IP real ---
BLOCKED_PATTERNS = [
    r"127\.0\.0\.1",
    r"localhost",
    r"0\.0\.0\.0",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
]

def is_blocked(url: str) -> bool:
    url_lower = url.lower()
    return any(re.search(p, url_lower) for p in BLOCKED_PATTERNS)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "falta parametro url"}), 400

    if is_blocked(url):
        return jsonify({"error": "URL bloqueada por el filtro de seguridad", "url_recibida": url}), 403

    try:
        resp = requests.get(url, timeout=3)
        return jsonify({"status": resp.status_code, "body": resp.text[:500]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5000)
