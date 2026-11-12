"""
fixed_app.py
------------
Version reforzada del endpoint /fetch. Aplica las 4 mitigaciones:

1. Resuelve el DNS y valida la IP REAL (no el string de la URL).
2. Allowlist de hosts permitidos en vez de denylist.
3. Desactiva redirects automaticos en el cliente HTTP (y no sigue
   redirects sin re-validar).
4. (Nota de infraestructura, no de codigo): el servicio que hace estos
   fetches deberia correr en una subred segmentada, sin rutas a
   169.254.169.254 (metadata cloud) ni a la red interna/privada.

Correr:
    pip install flask requests
    python fixed_app.py
Escucha en http://localhost:5001
"""

from flask import Flask, request, jsonify
import requests
import socket
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)

# --- 2. Allowlist de dominios permitidos (en vez de bloquear patrones) ---
ALLOWED_HOSTS = {
    "api.github.com",
    "jsonplaceholder.typicode.com",
}


@app.route("/internal/secret")
def secret():
    return jsonify({"info": "esto no deberia ser alcanzable via /fetch"})


def resolve_and_validate_ip(hostname: str) -> str:
    """Resuelve el hostname y valida que NINGUNA IP resuelta sea privada,
    loopback, link-local, reservada, etc. Lanza ValueError si es invalida."""
    infos = socket.getaddrinfo(hostname, None)
    ips = {info[4][0] for info in infos}

    if not ips:
        raise ValueError("no se pudo resolver el host")

    for ip_str in ips:
        ip = ipaddress.ip_address(ip_str)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError(f"IP resuelta no permitida: {ip_str}")

    return next(iter(ips))


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "falta parametro url"}), 400

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "esquema no permitido"}), 400

    hostname = parsed.hostname
    if not hostname or hostname not in ALLOWED_HOSTS:
        return jsonify({"error": "host no esta en la allowlist"}), 403

    # --- 1. Validar la IP real resuelta, no el string de la URL ---
    try:
        resolved_ip = resolve_and_validate_ip(hostname)
    except (ValueError, socket.gaierror) as e:
        return jsonify({"error": f"validacion de IP fallo: {e}"}), 403

    # --- 3. Sin redirects automaticos; si hay redirect, se corta ---
    try:
        resp = requests.get(url, timeout=3, allow_redirects=False)
        if resp.is_redirect or resp.is_permanent_redirect:
            return jsonify({
                "error": "la respuesta es un redirect; no se sigue automaticamente",
                "location": resp.headers.get("Location")
            }), 403

        return jsonify({
            "status": resp.status_code,
            "resolved_ip": resolved_ip,
            "body": resp.text[:500],
        })
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5001)
