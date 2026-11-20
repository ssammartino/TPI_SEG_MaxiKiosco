"""Demo local de SSRF por filtro textual. Ejecutar: python vulnerable_app.py."""

# Flask recibe las solicitudes; requests hace el fetch; re busca patrones.
from flask import Flask, request, jsonify, render_template_string
import requests
import re

app = Flask(__name__)


# Simula un recurso interno que la app no debería exponer.
@app.route("/internal/secret")
def secret():
    contenido = (
        "# .env interno - CONFIDENCIAL, no exponer fuera de la red interna\n"
        "DB_HOST=db-prod.internal.corp\n"
        "DB_USER=admin\n"
        "DB_PASSWORD=Correct_Horse_Battery_Staple_99!\n"
        "AWS_SECRET_ACCESS_KEY=FAKEAKIAEXAMPLE1234567890\n"
        "JWT_SIGNING_SECRET=s3cr3t_jwt_demo_no_usar_en_produccion\n"
        "ADMIN_PANEL_TOKEN=tkn_demo_9f8a7b6c5d4e\n"
    )
    # Flask arma la respuesta con el contenido, el código HTTP y el tipo de archivo.
    return contenido, 200, {"Content-Type": "text/plain"}


# Plantilla de la página; Jinja inserta aquí el error o el resultado del fetch.
INDEX_HTML = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>VideoPreview (demo vulnerable)</title>
</head>
<body style="font-family: sans-serif; max-width: 640px; margin: 48px auto; line-height:1.4;">
  <h1>🎬 VideoPreview</h1>
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
  <p style="color:#777; font-size:12px;">Backend: valida la URL con un filtro de patrones antes de hacer el fetch.</p>
</body>
</html>
"""


@app.route("/")
def index():
    # Renderiza el formulario inicialmente vacío.
    return render_template_string(INDEX_HTML, error=None, result=None, video_url="")


@app.route("/preview")
def preview():
    # Lee el enlace del formulario y lo filtra antes de solicitarlo.
    video_url = request.args.get("video_url", "")
    if not video_url:
        return render_template_string(INDEX_HTML, error=None, result=None, video_url="")

    if is_blocked(video_url):
        return render_template_string(
            INDEX_HTML,
            error="URL bloqueada por el filtro de seguridad",
            result=None,
            video_url=video_url,
        )

    try:
        # La petición sale desde el servidor; el filtro solo examinó el texto.
        resp = requests.get(video_url, timeout=3)
        resultado = f"Status: {resp.status_code}\n\n{resp.text[:800]}"
        return render_template_string(INDEX_HTML, error=None, result=resultado, video_url=video_url)
    except Exception as e:
        return render_template_string(INDEX_HTML, error=str(e), result=None, video_url=video_url)


# Regex conocidos como peligrosos; no comprueban a qué IP apunta el host.
BLOCKED_PATTERNS = [
    r"127\.0\.0\.1",
    r"localhost",
    r"0\.0\.0\.0",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
]


def is_blocked(url: str) -> bool:
    # Ignora mayúsculas y bloquea si encuentra cualquiera de los patrones.
    url_lower = url.lower()
    return any(re.search(p, url_lower) for p in BLOCKED_PATTERNS)


@app.route("/fetch")
def fetch():
    # Variante para pruebas: recibe la URL por query string y responde JSON.
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
