"""
================================================================================
 CASO 2 (VULNERABLE) - CSP Bypass vía JSONP / CDN Whitelist
================================================================================
 MaxiKiosco Online - Buscador de productos
 
 VULNERABILIDAD:
   El parámetro `q` se refleja SIN escapar dentro del HTML (XSS reflejado).
   La aplicación intenta mitigarlo con una Content-Security-Policy que
   restringe `script-src` a una whitelist de dominios de confianza:
 
       script-src 'self' https://cdnjs.cloudflare.com https://www.google.com
 
   Esto bloquea un <script>alert(1)</script> inline clásico (no hay
   'unsafe-inline'), PERO como la whitelist incluye CDNs públicos que
   alojan librerías "gadget" (AngularJS) o endpoints JSONP, un atacante
   puede cargar un script PERMITIDO por la CSP y usarlo para ejecutar
   JS arbitrario. Esto se conoce como "CSP bypass via whitelisted domains"
   o "JSONP/CDN script gadget bypass".
 
 EJECUTAR:
   pip install flask
   python vulnerable_app.py
   -> http://localhost:5002
================================================================================
"""
 
from flask import Flask, request, Response
import html
 
app = Flask(__name__)
 
PORT = 5002
 
# --------------------------------------------------------------------------
# Catálogo de productos de ejemplo
# --------------------------------------------------------------------------
PRODUCTOS = [
    {"nombre": "Coca-Cola 500ml", "precio": "$1200"},
    {"nombre": "Alfajor Jorgito", "precio": "$450"},
    {"nombre": "Papas Fritas Lays", "precio": "$900"},
    {"nombre": "Agua Mineral Villa del Sur", "precio": "$700"},
    {"nombre": "Chocolate Águila", "precio": "$600"},
]
 
 
def build_csp_header() -> str:
    """
    CSP basada en WHITELIST de dominios.
    Parece una buena práctica ('self' + dominios específicos, sin
    'unsafe-inline' ni 'unsafe-eval'), pero cdnjs.cloudflare.com y
    www.google.com alojan contenido que un atacante puede abusar.
    """
    return (
        "default-src 'self'; "
        # NOTA DE LA DEMO: 'unsafe-eval' se agrega acá a propósito para simular
        # un error de configuración MUY común en apps reales: equipos que lo
        # habilitan porque alguna librería legacy (como AngularJS) "lo necesita",
        # sin notar que, combinado con la whitelist de CDNs de abajo, habilita
        # ejecución de JS arbitrario (ver README, Bypass 1).
        "script-src 'self' 'unsafe-eval' https://cdnjs.cloudflare.com https://www.google.com; "
        "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://www.google.com https://cdnjs.cloudflare.com; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
 
 
PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>MaxiKiosco Online - Buscador</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin:0; padding:0; }}
        header {{ background:#c0392b; color:white; padding:20px; }}
        .container {{ max-width: 900px; margin: 20px auto; padding: 0 20px; }}
        .search-box {{ display:flex; margin-bottom:20px; }}
        .search-box input {{ flex:1; padding:10px; font-size:16px; border:1px solid #ccc; }}
        .search-box button {{ padding:10px 20px; background:#c0392b; color:white; border:none; cursor:pointer; }}
        .result-banner {{ background:white; padding:15px; border-left:4px solid #c0392b; margin-bottom:20px; }}
        table {{ width:100%; border-collapse: collapse; background:white; }}
        th, td {{ padding:10px; border-bottom:1px solid #ddd; text-align:left; }}
        th {{ background:#eee; }}
        .csp-panel {{ background:#2c3e50; color:#ecf0f1; padding:15px; margin-top:30px; font-size:13px; border-radius:4px; }}
        .csp-panel code {{ color:#f1c40f; word-break: break-all; }}
        .badge-vuln {{ background:#e74c3c; color:white; padding:3px 10px; border-radius:4px; font-size:12px; }}
    </style>
</head>
<body>
    <header>
        <h1>🏪 MaxiKiosco Online <span class="badge-vuln">VERSIÓN VULNERABLE (5002)</span></h1>
    </header>
    <div class="container">
        <form class="search-box" method="GET" action="/">
            <input type="text" name="q" placeholder="Buscar producto..." value="{q_raw_attr}">
            <button type="submit">Buscar</button>
        </form>
 
        {result_banner}
 
        <table>
            <tr><th>Producto</th><th>Precio</th></tr>
            {productos_rows}
        </table>
 
        <div class="csp-panel">
            <strong>🛡️ Content-Security-Policy enviada por el servidor:</strong><br>
            <code>{csp_value}</code>
            <br><br>
            <strong>⚠️ Por qué "parece" segura y no lo es:</strong>
            <ul>
                <li>No tiene <code>'unsafe-inline'</code> → un <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> inyectado NO se ejecuta.</li>
                <li>Pero permite <code>https://cdnjs.cloudflare.com</code> (podés cargar AngularJS y abusar de sus templates/expresiones).</li>
                <li>Y permite <code>https://www.google.com</code> (endpoints JSONP que ejecutan un callback arbitrario como script "legítimo").</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
 
 
@app.route("/")
def index():
    q = request.args.get("q", "")
 
    # --------------------------------------------------------------------
    # *** VULNERABILIDAD: reflejar `q` sin escapar dentro del HTML ***
    # --------------------------------------------------------------------
    if q:
        result_banner = f"""
        <div class="result-banner">
            Resultados para: {q}
        </div>
        """
        # atributo value="" sí lo escapamos minimamente para no romper el input,
        # pero esto NO es la vulnerabilidad principal (la banda de arriba sí lo es)
        q_raw_attr = html.escape(q, quote=True)
    else:
        result_banner = ""
        q_raw_attr = ""
 
    productos_rows = "".join(
        f"<tr><td>{p['nombre']}</td><td>{p['precio']}</td></tr>" for p in PRODUCTOS
    )
 
    csp_value = build_csp_header()
 
    page = PAGE_TEMPLATE.format(
        q_raw_attr=q_raw_attr,
        result_banner=result_banner,
        productos_rows=productos_rows,
        csp_value=csp_value,
    )
 
    resp = Response(page, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = csp_value
    return resp
 
 
if __name__ == "__main__":
    print(f"[Caso 2 - VULNERABLE] corriendo en http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=True)