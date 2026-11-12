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

from flask import Flask, request, jsonify, render_template_string
import requests
import re

app = Flask(__name__)  # instancia principal de la app Flask; __name__ le dice
                        # a Flask donde esta el archivo para ubicar recursos


# --- "Archivo interno" simulado: lo que un atacante quiere robar via SSRF.
# Simula un .env filtrado con credenciales (todo ficticio, solo para la demo).
@app.route("/internal/secret")
def secret():
    # En la vida real esto seria un servicio que SOLO deberia responder a
    # pedidos que vienen de la propia red interna (no desde internet).
    # La idea del ejercicio es que /fetch, corriendo en el mismo servidor,
    # SI puede llegar hasta aca (porque esta en localhost), y por eso es
    # un objetivo jugoso para un ataque SSRF.
    contenido = (
        "# .env interno - CONFIDENCIAL, no exponer fuera de la red interna\n"
        "DB_HOST=db-prod.internal.corp\n"
        "DB_USER=admin\n"
        "DB_PASSWORD=Correct_Horse_Battery_Staple_99!\n"
        "AWS_SECRET_ACCESS_KEY=FAKEAKIAEXAMPLE1234567890\n"
        "JWT_SIGNING_SECRET=s3cr3t_jwt_demo_no_usar_en_produccion\n"
        "ADMIN_PANEL_TOKEN=tkn_demo_9f8a7b6c5d4e\n"
    )
    # Devolvemos una tupla (body, status_code, headers) en vez de jsonify():
    # Flask interpreta esa tupla y arma la respuesta HTTP con ese texto plano,
    # ese codigo de estado y esos headers. Content-Type: text/plain hace que
    # se vea como un archivo de texto crudo, no como JSON.
    return contenido, 200, {"Content-Type": "text/plain"}


# --- Front simple: "pega el link de tu video y te mostramos una vista previa" ---
# Esta es una plantilla Jinja2 (el motor de templates que usa Flask). Las
# cosas entre {{ }} son variables que se reemplazan por su valor real, y
# {% if %}...{% endif %} son bloques condicionales: ese HTML solo aparece
# si la condicion es verdadera. Todo esto se resuelve en el servidor antes
# de mandarle el HTML final al navegador.
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
    # render_template_string reemplaza las variables Jinja del HTML de
    # arriba por estos valores. Como error/result son None y video_url
    # esta vacio, la pagina se muestra "en blanco" (sin error ni resultado).
    return render_template_string(INDEX_HTML, error=None, result=None, video_url="")


@app.route("/preview")
def preview():
    # request.args.get lee un query param de la URL, ej: /preview?video_url=...
    # El segundo argumento ("") es el valor por defecto si no vino el parametro.
    video_url = request.args.get("video_url", "")
    if not video_url:
        return render_template_string(INDEX_HTML, error=None, result=None, video_url="")

    # Aca se aplica el filtro "ingenuo" (definido mas abajo en el archivo;
    # en Python esto funciona porque is_blocked ya existe cuando esta
    # funcion se EJECUTA, aunque este escrita despues en el archivo).
    if is_blocked(video_url):
        return render_template_string(
            INDEX_HTML,
            error="URL bloqueada por el filtro de seguridad",
            result=None,
            video_url=video_url,
        )

    try:
        # Esta es la parte vulnerable: el servidor hace un pedido HTTP a
        # CUALQUIER url que haya pasado el filtro, sin volver a chequear
        # a que IP termino resolviendo realmente esa url.
        resp = requests.get(video_url, timeout=3)
        # resp.text[:800] corta la respuesta a los primeros 800 caracteres,
        # solo para que no explote la pagina si la respuesta es gigante.
        resultado = f"Status: {resp.status_code}\n\n{resp.text[:800]}"
        return render_template_string(INDEX_HTML, error=None, result=resultado, video_url=video_url)
    except Exception as e:
        # Si el fetch falla (timeout, host inexistente, etc.) mostramos el
        # error en la misma pagina en vez de que la app se caiga.
        return render_template_string(INDEX_HTML, error=str(e), result=None, video_url=video_url)


# --- Filtro ingenuo: bloquea por patrones de texto, no valida la IP real ---
# Cada entrada es una expresion regular (regex) que busca un patron de texto
# conocido como "peligroso". El problema de fondo: esto compara el STRING
# de la url, no la IP a la que realmente apunta esa url una vez resuelta.
BLOCKED_PATTERNS = [
    r"127\.0\.0\.1",                                      # el "\." escapa el punto literal (sino "." significa "cualquier caracter" en regex)
    r"localhost",                                         # nombre comun de loopback
    r"0\.0\.0\.0",                                        # otra forma de referirse a "esta maquina"
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",                 # rango privado 10.0.0.0/8 (\d{1,3} = 1 a 3 digitos, \b = limite de palabra)
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",                    # rango privado 192.168.0.0/16
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",    # rango privado 172.16.0.0/12 (el segundo octeto va de 16 a 31)
]

def is_blocked(url: str) -> bool:
    # Pasamos todo a minuscula para no dejar pasar "LOCALHOST" o "LocalHost".
    url_lower = url.lower()
    # any(...) devuelve True si ALGUNO de los patrones matchea en algun
    # lugar del string (re.search busca en cualquier posicion, no solo al
    # principio). O sea: alcanza con que aparezca una sola de estas
    # substrings en cualquier parte de la url para que se bloquee.
    return any(re.search(p, url_lower) for p in BLOCKED_PATTERNS)


@app.route("/fetch")
def fetch():
    # Mismo endpoint que /preview pero pensado para ser llamado por script
    # (devuelve JSON en vez de HTML). Lo usa attack_demo.py.
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "falta parametro url"}), 400  # 400 = Bad Request

    if is_blocked(url):
        return jsonify({"error": "URL bloqueada por el filtro de seguridad", "url_recibida": url}), 403  # 403 = Forbidden

    try:
        resp = requests.get(url, timeout=3)  # timeout=3: si no responde en 3s se corta (evita que la app quede colgada)
        return jsonify({"status": resp.status_code, "body": resp.text[:500]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # 500 = error interno del servidor


if __name__ == "__main__":
    # Esto solo se ejecuta si corres "python vulnerable_app.py" directamente
    # (no si este archivo se importa desde otro script). Arranca el
    # servidor de desarrollo de Flask en el puerto 5000.
    app.run(port=5000)
