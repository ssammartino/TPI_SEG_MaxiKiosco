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

from flask import Flask, request, jsonify, render_template_string
import requests
import socket
import ipaddress
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection as Urllib3HTTPConnection
from urllib3.connection import HTTPSConnection as Urllib3HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import PoolManager

app = Flask(__name__)

# --- 2. Allowlist de dominios permitidos (en vez de bloquear patrones) ---
# Para el caso de uso "pegá el link de tu video" sumamos los dominios reales
# que necesitaría una funcionalidad de preview de YouTube.
ALLOWED_HOSTS = {
    "api.github.com",
    "jsonplaceholder.typicode.com",
    "www.youtube.com",
    "youtube.com",
    "youtu.be",
    "img.youtube.com",
}


class _PinnedConnectionMixin:
    _pinned_ip: str

    def _new_conn(self):
        # Pin only the TCP destination; keep the original hostname for Host and TLS validation.
        original_dns_host = self._dns_host
        self._dns_host = self._pinned_ip
        try:
            return super()._new_conn()
        finally:
            self._dns_host = original_dns_host


class _PinnedHTTPConnection(_PinnedConnectionMixin, Urllib3HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, Urllib3HTTPSConnection):
    pass


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection
    _pinned_ip: str

    def _new_conn(self):
        conn = super()._new_conn()
        conn._pinned_ip = self._pinned_ip
        return conn


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection
    _pinned_ip: str

    def _new_conn(self):
        conn = super()._new_conn()
        conn._pinned_ip = self._pinned_ip
        return conn


class _PinnedPoolManager(PoolManager):
    def __init__(self, pinned_ip: str, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(**kwargs)
        self.pool_classes_by_scheme = dict(self.pool_classes_by_scheme)
        self.pool_classes_by_scheme["http"] = _PinnedHTTPConnectionPool
        self.pool_classes_by_scheme["https"] = _PinnedHTTPSConnectionPool

    def _new_pool(self, scheme, host, port, *args, **kwargs):
        pool = super()._new_pool(scheme, host, port, *args, **kwargs)
        pool._pinned_ip = self._pinned_ip
        return pool


class _PinnedHTTPAdapter(HTTPAdapter):
    def __init__(self, pinned_ip: str):
        self._pinned_ip = pinned_ip
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = _PinnedPoolManager(
            self._pinned_ip,
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


@app.route("/internal/secret")
def secret():
    return jsonify({"info": "esto no deberia ser alcanzable via /fetch"})


# --- Mismo front que la version vulnerable, para comparar lado a lado ---
INDEX_HTML = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>VideoPreview (demo reforzada)</title>
</head>
<body style="font-family: sans-serif; max-width: 640px; margin: 48px auto; line-height:1.4;">
  <h1>🎬 VideoPreview (reforzado)</h1>
  <p>Pegá el link de un video (YouTube u otro) y te mostramos una vista previa del contenido.</p>
  <form action="/preview" method="get">
    <input type="text" name="video_url" placeholder="https://www.youtube.com/watch?v=..."
           style="width:70%; padding:8px; font-size:14px;" value="{{ video_url|default('') }}">
    <button type="submit" style="padding:8px 16px; font-size:14px;">Vista previa</button>
  </form>

  {% if error %}
    <p style="color:#b00020;"><b>Error:</b> {{ error }}</p>
  {% endif %}

  {% if result %}
    <h3>Resultado:</h3>
    <pre style="background:#f4f4f4; padding:12px; white-space:pre-wrap; word-break:break-all;">{{ result }}</pre>
  {% endif %}

  <hr>
  <p style="color:#777; font-size:12px;">Backend: resuelve y valida la IP real, allowlist de hosts, sin redirects automaticos.</p>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML, error=None, result=None, video_url="")


@app.route("/preview")
def preview_ui():
    video_url = request.args.get("video_url", "")
    if not video_url:
        return render_template_string(INDEX_HTML, error=None, result=None, video_url="")

    parsed = urlparse(video_url)
    hostname = parsed.hostname

    if parsed.scheme not in ("http", "https") or not hostname or hostname not in ALLOWED_HOSTS:
        return render_template_string(
            INDEX_HTML, error="Host no permitido (no esta en la allowlist)",
            result=None, video_url=video_url,
        )

    try:
        resp, _ = request_validated_url(video_url, parsed.scheme, hostname)
        if resp.is_redirect or resp.is_permanent_redirect:
            return render_template_string(
                INDEX_HTML, error="Redirect bloqueado (no se sigue automaticamente)",
                result=None, video_url=video_url,
            )
        resultado = f"Status: {resp.status_code}\n\n{resp.text[:800]}"
        return render_template_string(INDEX_HTML, error=None, result=resultado, video_url=video_url)
    except (ValueError, socket.gaierror) as e:
        return render_template_string(
            INDEX_HTML, error=f"Validacion de IP fallo: {e}", result=None, video_url=video_url,
        )
    except requests.RequestException as e:
        return render_template_string(INDEX_HTML, error=str(e), result=None, video_url=video_url)


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


def request_validated_url(url: str, scheme: str, hostname: str):
    resolved_ip = resolve_and_validate_ip(hostname)
    with requests.Session() as session:
        session.trust_env = False
        session.mount(f"{scheme}://", _PinnedHTTPAdapter(resolved_ip))
        response = session.get(url, timeout=3, allow_redirects=False)
    return response, resolved_ip


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

    try:
        resp, resolved_ip = request_validated_url(url, parsed.scheme, hostname)
    except (ValueError, socket.gaierror) as e:
        return jsonify({"error": f"validacion de IP fallo: {e}"}), 403
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

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


if __name__ == "__main__":
    app.run(port=5001)
