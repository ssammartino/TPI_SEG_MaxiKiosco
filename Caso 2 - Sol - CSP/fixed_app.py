"""
================================================================================
 CASO 2 (SEGURO) - CSP con Nonce + 'strict-dynamic' + Escape de Input
================================================================================
 MaxiKiosco Online - Buscador de productos (versión corregida)

 CORRECCIONES respecto a la versión vulnerable (puerto 5002):

   1) ESCAPE DEL INPUT:
      `q` se renderiza con `render_template_string` + Jinja2 AUTOESCAPE
      activado (comportamiento por defecto de Flask). Nunca se usa `|safe`
      ni se concatena HTML a mano. Cualquier `<`, `>`, `"`, `'` en `q` se
      convierte en su entidad HTML (&lt;, &gt;, etc.) → el navegador lo
      muestra como TEXTO, nunca lo interpreta como markup/script nuevo.

   2) CSP CON NONCE + 'strict-dynamic':
      - Se genera un nonce aleatorio (criptográficamente seguro) en CADA
        request, con `secrets.token_urlsafe`.
      - Solo los <script nonce="EL_NONCE_DE_ESTA_RESPONSE"> ejecutan.
      - 'strict-dynamic' le dice al navegador: "un script con nonce válido
        puede, a su vez, cargar otros scripts dinámicamente (p.ej. vía
        document.createElement('script')), y esos heredan la confianza".
        Esto reemplaza la necesidad de whitelistear dominios de CDN:
        ya no importa si cdnjs o google.com están "permitidos" o no,
        porque lo que importa es el NONCE, no el origen.
      - NO HAY 'unsafe-inline' NI 'unsafe-eval': un atacante que logre
        inyectar `<script>...</script>` sin el nonce correcto (porque no
        puede predecirlo, es aleatorio por request) no logra ejecutar nada.
        Tampoco puede usar gadgets tipo AngularJS (constructor.constructor)
        porque el motor de `eval`/`Function` está bloqueado.

   3) (Bonus) HASH SHA-256 para el único script inline fijo de la página
      (un snippet mínimo de UI), como alternativa al nonce para contenido
      que no cambia entre requests.

 EJECUTAR:
   pip install flask
   python fixed_app.py
   -> http://localhost:5003
================================================================================
"""

import base64
import hashlib
import secrets

from flask import Flask, request, Response, render_template_string

app = Flask(__name__)

PORT = 5003

PRODUCTOS = [
    {"nombre": "Coca-Cola 500ml", "precio": "$1200"},
    {"nombre": "Alfajor Jorgito", "precio": "$450"},
    {"nombre": "Papas Fritas Lays", "precio": "$900"},
    {"nombre": "Agua Mineral Villa del Sur", "precio": "$700"},
    {"nombre": "Chocolate Águila", "precio": "$600"},
]

# --------------------------------------------------------------------------
# Script inline FIJO (nunca cambia) -> lo protegemos con un hash SHA-256
# en vez de nonce, para mostrar la alternativa que ofrece la CSP.
# --------------------------------------------------------------------------
INLINE_UI_SCRIPT = (
    "document.addEventListener('DOMContentLoaded', function () {"
    "  var f = document.querySelector('.search-box');"
    "  if (f) { f.querySelector('input').focus(); }"
    "});"
)


def compute_sha256_hash(script_content: str) -> str:
    """Calcula el hash sha256-<base64> que la CSP espera para un script
    inline de contenido fijo (debe coincidir carácter por carácter)."""
    digest = hashlib.sha256(script_content.encode("utf-8")).digest()
    b64 = base64.b64encode(digest).decode("utf-8")
    return f"sha256-{b64}"


def build_csp_header(nonce: str, inline_hash: str) -> str:
    """
    CSP moderna basada en NONCE + 'strict-dynamic', en vez de whitelist
    de dominios. Esto es lo que recomienda OWASP y el propio Google como
    reemplazo de las whitelists de CDN (que son bypasseables, como vimos
    en el Caso 2 - Vulnerable).
    """
    return (
        "default-src 'self'; "
        f"script-src 'nonce-{nonce}' 'strict-dynamic' '{inline_hash}' 'self'; "
        "style-src 'self' 'unsafe-inline'; "  # estilos inline son menos riesgosos; se podría mover a hash también
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>MaxiKiosco Online - Buscador (Seguro)</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; margin:0; padding:0; }
        header { background:#27ae60; color:white; padding:20px; }
        .container { max-width: 900px; margin: 20px auto; padding: 0 20px; }
        .search-box { display:flex; margin-bottom:20px; }
        .search-box input { flex:1; padding:10px; font-size:16px; border:1px solid #ccc; }
        .search-box button { padding:10px 20px; background:#27ae60; color:white; border:none; cursor:pointer; }
        .result-banner { background:white; padding:15px; border-left:4px solid #27ae60; margin-bottom:20px; white-space: pre-wrap; }
        table { width:100%; border-collapse: collapse; background:white; }
        th, td { padding:10px; border-bottom:1px solid #ddd; text-align:left; }
        th { background:#eee; }
        .csp-panel { background:#1e272e; color:#ecf0f1; padding:15px; margin-top:30px; font-size:13px; border-radius:4px; }
        .csp-panel code { color:#2ecc71; word-break: break-all; }
        .badge-safe { background:#27ae60; color:white; padding:3px 10px; border-radius:4px; font-size:12px; }
        .compare { display:flex; gap:15px; margin-top:15px; flex-wrap: wrap;}
        .compare .col { flex:1; min-width:280px; background:#111; padding:10px; border-radius:4px; }
        .compare .col h4 { margin-top:0; }
        .compare .vuln-col { border-left:3px solid #e74c3c; }
        .compare .safe-col { border-left:3px solid #2ecc71; }
    </style>
</head>
<body>
    <header>
        <h1>🏪 MaxiKiosco Online <span class="badge-safe">VERSIÓN SEGURA (5003)</span></h1>
    </header>
    <div class="container">
        <form class="search-box" method="GET" action="/">
            <input type="text" name="q" placeholder="Buscar producto..." value="{{ q }}">
            <button type="submit">Buscar</button>
        </form>

        {% if q %}
        <div class="result-banner">Resultados para: {{ q }}</div>
        {% endif %}

        <table>
            <tr><th>Producto</th><th>Precio</th></tr>
            {% for p in productos %}
            <tr><td>{{ p.nombre }}</td><td>{{ p.precio }}</td></tr>
            {% endfor %}
        </table>

        <div class="csp-panel">
            <strong>🛡️ Content-Security-Policy enviada por el servidor (nonce cambia en cada request):</strong><br>
            <code>{{ csp_value }}</code>

            <div class="compare">
                <div class="col vuln-col">
                    <h4>❌ Vulnerable (5002)</h4>
                    <ul>
                        <li><code>q</code> se refleja SIN escapar</li>
                        <li>CSP por whitelist de dominios (cdnjs, google.com)</li>
                        <li><code>'unsafe-eval'</code> presente</li>
                        <li>Bypass: cargar script "gadget" desde dominio permitido</li>
                    </ul>
                </div>
                <div class="col safe-col">
                    <h4>✅ Segura (5003)</h4>
                    <ul>
                        <li><code>q</code> se renderiza escapado (Jinja2 autoescape)</li>
                        <li>CSP por <code>nonce</code> + <code>'strict-dynamic'</code></li>
                        <li>Sin <code>'unsafe-inline'</code> ni <code>'unsafe-eval'</code></li>
                        <li>El nonce es aleatorio por request → imposible de predecir/inyectar</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <script nonce="{{ nonce }}">{{ inline_ui_script | safe }}</script>
</body>
</html>
"""


@app.route("/")
def index():
    q = request.args.get("q", "")

    # Nonce aleatorio y distinto en cada response (no reutilizable, no predecible)
    nonce = secrets.token_urlsafe(16)
    inline_hash = compute_sha256_hash(INLINE_UI_SCRIPT)
    csp_value = build_csp_header(nonce, inline_hash)

    # render_template_string con Jinja2 AUTOESCAPE (default en Flask) =>
    # `q` y los campos de `productos` se escapan automáticamente.
    # Nunca usamos |safe sobre datos que vienen del usuario.
    page = render_template_string(
        PAGE_TEMPLATE,
        q=q,
        productos=PRODUCTOS,
        csp_value=csp_value,
        nonce=nonce,
        inline_ui_script=INLINE_UI_SCRIPT,
    )

    resp = Response(page, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = csp_value
    # Headers adicionales de buena práctica (no estrictamente parte de la demo de CSP,
    # pero coherentes con "versión segura")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


if __name__ == "__main__":
    print(f"[Caso 2 - SEGURO] corriendo en http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
