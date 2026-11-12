"""
vulnerable_app_resolve_check.py
--------------------------------
Variante "a medio camino" entre vulnerable_app.py y fixed_app.py: en vez de
un regex sobre el string, ACA SI resolvemos el hostname y validamos que la
IP resuelta no sea privada/loopback (como el punto 1 de las mitigaciones).

Pero el bug sigue ahi: validamos con UNA resolucion de DNS, y el fetch real
(requests.get) hace OTRA resolucion por separado, sin reusar la IP que ya
validamos. Ese gap entre "valide" y "me conecte" es EXACTAMENTE lo que
explota un DNS rebinding: si el servidor DNS responde distinto en la
segunda consulta, el validador nunca se entera.

Correr:
    pip install flask requests
    python vulnerable_app_resolve_check.py
Escucha en http://localhost:5000

Para probar el rebinding contra ESTA app, no la corras directo: usala a
traves de run_with_fake_dns.py (ver ese archivo y el README).
"""

from flask import Flask, request, render_template_string
import requests
import socket
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)


@app.route("/internal/secret")
def secret():
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


def es_ip_privada(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def validar_host(hostname: str) -> str:
    """PASO 1 (validacion): resuelve el hostname AHORA MISMO y chequea que
    la IP no sea privada. Esto parece correcto -- el problema es que nadie
    reusa esta IP despues; el fetch real (mas abajo) resuelve de nuevo."""
    infos = socket.getaddrinfo(hostname, None)
    ips = {info[4][0] for info in infos}
    for ip_str in ips:
        if es_ip_privada(ip_str):
            raise ValueError(f"IP resuelta no permitida: {ip_str}")
    return next(iter(ips))


@app.route("/")
def index():
    return render_template_string(INDEX_HTML, error=None, result=None, video_url="")


@app.route("/preview")
def preview():
    video_url = request.args.get("video_url", "")
    if not video_url:
        return render_template_string(INDEX_HTML, error=None, result=None, video_url="")

    hostname = urlparse(video_url).hostname
    if not hostname:
        return render_template_string(INDEX_HTML, error="URL invalida", result=None, video_url=video_url)

    try:
        ip_validacion = validar_host(hostname)
    except (ValueError, socket.gaierror) as e:
        return render_template_string(
            INDEX_HTML, error=f"Validacion de IP fallo: {e}", result=None, video_url=video_url
        )

    # --- BUG: esta llamada hace SU PROPIA resolucion de DNS internamente,
    # distinta de la que ya hicimos en validar_host(). Si el DNS cambio la
    # respuesta entre medio, aca termina pegando contra otra IP distinta
    # a la que "validamos" arriba. ---
    try:
        resp = requests.get(video_url, timeout=3)
        resultado = f"(IP validada: {ip_validacion})\nStatus: {resp.status_code}\n\n{resp.text[:800]}"
        return render_template_string(INDEX_HTML, error=None, result=resultado, video_url=video_url)
    except Exception as e:
        return render_template_string(INDEX_HTML, error=str(e), result=None, video_url=video_url)


if __name__ == "__main__":
    app.run(port=5000)
