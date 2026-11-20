"""Demo local de DNS rebinding: valida el host, pero no fija la IP al conectar."""

# Flask sirve las rutas; requests hace el fetch; socket resuelve DNS;
# ipaddress clasifica IPs y urlparse extrae el host de la URL.
from flask import Flask, request, render_template_string
import requests
import socket
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)


@app.route("/internal/secret")
def secret():
    # Respuesta ficticia para que la demo tenga un recurso interno local.
    contenido = (
        "# .env interno - CONFIDENCIAL, no exponer fuera de la red interna\n"
        "DB_PASSWORD=Correct_Horse_Battery_Staple_99!\n"
        "AWS_SECRET_ACCESS_KEY=FAKEAKIAEXAMPLE1234567890\n"
        "JWT_SIGNING_SECRET=s3cr3t_jwt_demo_no_usar_en_produccion\n"
    )
    return contenido, 200, {"Content-Type": "text/plain"}


INDEX_HTML = """
<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>VideoPreview (valida IP, pero rebindeable)</title></head>
<body style="font-family: sans-serif; max-width: 640px; margin: 48px auto; line-height:1.4;">
  <h1>🎬 VideoPreview (con validacion de IP)</h1>
  <p>Pegá el link de un video y te mostramos una vista previa. Esta version
     SI valida la IP resuelta del host antes de continuar.</p>
  <form action="/preview" method="get">
    <input type="text" name="video_url" placeholder="https://www.youtube.com/watch?v=..."
           style="width:70%; padding:8px; font-size:14px;" value="{{ video_url|default('') }}">
    <button type="submit" style="padding:8px 16px; font-size:14px;">Vista previa</button>
  </form>
  {% if error %}<p style="color:#b00020;"><b>Error:</b> {{ error }}</p>{% endif %}
  {% if result %}<h3>Resultado:</h3><pre style="background:#f4f4f4; padding:12px; white-space:pre-wrap; word-break:break-all;">{{ result }}</pre>{% endif %}
</body>
</html>
"""


# ipaddress interpreta la dirección y expone estas categorías como booleanos.
def es_ip_privada(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    # Si cualquiera es True, la IP no se considera un destino público seguro.
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def validar_host(hostname: str) -> str:
    """Resuelve el host y rechaza respuestas privadas o especiales."""
    # DNS puede devolver varias direcciones; se rechaza el host si alguna es privada.
    infos = socket.getaddrinfo(hostname, None)
    ips = {info[4][0] for info in infos}
    for ip_str in ips:
        if es_ip_privada(ip_str):
            raise ValueError(f"IP resuelta no permitida: {ip_str}")
    return next(iter(ips))


@app.route("/")
def index():
    # Muestra el formulario sin resultados.
    return render_template_string(INDEX_HTML, error=None, result=None, video_url="")


@app.route("/preview")
def preview():
    # Obtiene la URL y extrae el nombre de host que se consultará en DNS.
    video_url = request.args.get("video_url", "")
    if not video_url:
        return render_template_string(INDEX_HTML, error=None, result=None, video_url="")

    hostname = urlparse(video_url).hostname
    if not hostname:
        return render_template_string(INDEX_HTML, error="URL invalida", result=None, video_url=video_url)

    try:
        # Esta IP se valida aquí, pero no se entrega a requests para conectarse.
        ip_validacion = validar_host(hostname)
    except (ValueError, socket.gaierror) as e:
        return render_template_string(
            INDEX_HTML, error=f"Validacion de IP fallo: {e}", result=None, video_url=video_url
        )

    # requests recibe el nombre original y hace otra resolución al conectar.
    # Si DNS responde distinto, esta conexión no usa necesariamente la IP validada.
    try:
        resp = requests.get(video_url, timeout=3)
        resultado = f"(IP validada: {ip_validacion})\nStatus: {resp.status_code}\n\n{resp.text[:800]}"
        return render_template_string(INDEX_HTML, error=None, result=resultado, video_url=video_url)
    except Exception as e:
        return render_template_string(INDEX_HTML, error=str(e), result=None, video_url=video_url)


if __name__ == "__main__":
    app.run(port=5000)
