"""
Servidor de correo VULNERABLE a JKU Header Injection.

El punto débil está en `verificar_token()`: si el JWT trae un header `jku`,
el servidor se baja la clave pública desde esa URL (controlada por el
atacante) y valida la firma con ella. Un atacante puede forjar un token
firmado con SU propia clave, hostear SU clave pública y hacer que el
servidor la use para validar => bypass de autenticacion.
"""
import json

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Clave propia del servidor (se genera al arrancar). Con ESTA clave firma los
# tokens legitimos y con ella deberia validarlos SIEMPRE.
# ---------------------------------------------------------------------------
_clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SERVER_PRIVATE_PEM = _clave.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
SERVER_PUBLIC_PEM = _clave.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# ---------------------------------------------------------------------------
# "Base de datos" en memoria: usuarios, contrasenas y bandejas.
# ---------------------------------------------------------------------------
USUARIOS = {
    "pedro": {
        "password": "pedro123",
        "inbox": [
            {"de": "cumple@gmail.com", "asunto": "Fiesta el sabado", "cuerpo": "Te espero a las 21hs."},
            {"de": "newsletter@python.org", "asunto": "Python Weekly", "cuerpo": "Novedades de la semana."},
        ],
    },
    "admin": {
        "password": "admin123",
        "inbox": [
            {"de": "ceo@empresa.com", "asunto": "Credenciales produccion", "cuerpo": "root / S3cr3t0-Prod-2024"},
            {"de": "banco@empresa.com", "asunto": "Transferencia pendiente", "cuerpo": "Aprobar USD 250.000 a cuenta 0099."},
            {"de": "legal@empresa.com", "asunto": "Contrato confidencial", "cuerpo": "No reenviar: fusion con ACME."},
        ],
    },
}


# ===========================================================================
#  AQUI ESTA LA VULNERABILIDAD
# ===========================================================================
def verificar_token(token):
    """Valida la firma del JWT.

    BUG: si el header trae `jku`, se baja la clave de esa URL y valida con
    ella. El token legitimo (sin jku) valida con la clave del servidor; el
    token del atacante (con jku) hace que el server use una clave externa.
    """
    header = jwt.get_unverified_header(token)

    if "jku" in header:
        # <-- El agujero: confiamos en una URL que viene DENTRO del token.
        respuesta = requests.get(header["jku"], timeout=5)
        jwks = respuesta.json()
        jwk = jwks["keys"][0]
        clave_publica = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    else:
        # Camino legitimo: usamos nuestra propia clave.
        clave_publica = SERVER_PUBLIC_PEM

    # Nota: aunque fijamos RS256, la clave ya fue elegida por el atacante.
    return jwt.decode(token, clave_publica, algorithms=["RS256"])


# ===========================================================================
#  Rutas
# ===========================================================================
@app.route("/")
def index():
    return render_template("login.html")


@app.route("/bandeja")
def bandeja():
    # Pantalla del inbox (HTML). Los datos los pide por fetch a /inbox.
    return render_template("inbox.html")


@app.route("/login", methods=["POST"])
def login():
    usuario = request.json.get("usuario") if request.is_json else request.form.get("usuario")
    password = request.json.get("password") if request.is_json else request.form.get("password")

    datos = USUARIOS.get(usuario)
    if not datos or datos["password"] != password:
        return jsonify({"error": "Credenciales invalidas"}), 401

    # Token legitimo: header {alg, typ} SIN jku, firmado con la clave del server.
    token = jwt.encode({"user": usuario}, SERVER_PRIVATE_PEM, algorithm="RS256")
    return jsonify({"token": token})


@app.route("/inbox")
def inbox():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Falta el header Authorization: Bearer <token>"}), 401

    token = auth.split(" ", 1)[1]
    try:
        payload = verificar_token(token)
    except Exception as e:  # noqa: BLE001  (demo)
        return jsonify({"error": f"Token invalido: {e}"}), 401

    usuario = payload.get("user")
    datos = USUARIOS.get(usuario)
    if not datos:
        return jsonify({"error": "Usuario desconocido"}), 404

    return jsonify({"usuario": usuario, "inbox": datos["inbox"]})


if __name__ == "__main__":
    print("=" * 60)
    print(" Servidor VULNERABLE escuchando en http://localhost:5000")
    print(" Usuarios:  pedro/pedro123   admin/admin123")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
