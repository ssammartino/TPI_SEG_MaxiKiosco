"""
Servidor de correo CORREGIDO.

Es identico al vulnerable salvo por `verificar_token()`: aqui se IGNORA por
completo el header `jku` (y `jwk`). El servidor valida SIEMPRE con su propia
clave publica y fija el algoritmo a RS256. No importa que mande el atacante
en el header: la firma solo valida si fue hecha con la clave privada del
servidor, que el atacante no tiene.
"""
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

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
#  VERSION CORREGIDA
# ===========================================================================
def verificar_token(token):
    """Valida la firma usando SIEMPRE la clave propia del servidor.

    Se ignoran `jku` y `jwk` del header. Si alguien manda un token firmado
    con otra clave, la verificacion falla.
    """
    return jwt.decode(token, SERVER_PUBLIC_PEM, algorithms=["RS256"])


# ===========================================================================
#  Rutas (identicas al servidor vulnerable)
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
    print(" Servidor CORREGIDO escuchando en http://localhost:5001")
    print(" Usuarios:  pedro/pedro123   admin/admin123")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5001, debug=False)
