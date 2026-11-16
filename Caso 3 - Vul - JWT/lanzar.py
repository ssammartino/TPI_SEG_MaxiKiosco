"""
LANZADOR — un solo comando levanta toda la demo del Caso 3 (VULNERABLE).

    python lanzar.py

Arranca, en segundo plano:
  - el servidor VULNERABLE   -> http://localhost:5000  (WebMail)
  - la maquina del ATACANTE  -> http://localhost:9000  (claves + JWKS)

y abre el navegador en la WebMail, donde arranca tu demo.

Flujo de la demo (lo hacés vos con Burp):
  1. logueate en  http://localhost:5000  como pedro/pedro123
  2. interceptá con Burp y mandá la request de /inbox al Repeater
  3. en http://localhost:9000  copiá la clave del atacante y la linea jku
  4. en Burp (JWT Editor): user=admin, agregá el jku y firmá -> token nuevo
  5. Send en el Repeater -> ves la bandeja del admin

Para cortar: Ctrl+C.
"""
import socket
import threading
import time
import webbrowser

from werkzeug.serving import make_server

import atacante
import servidor_vulnerable


def puerto_libre(puerto):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", puerto)) != 0


def correr(app, puerto):
    make_server("0.0.0.0", puerto, app, threaded=True).serve_forever()


if __name__ == "__main__":
    print("=" * 64)
    print(" CASO 3 - JWT JKU Injection  |  INSTANCIA VULNERABLE")
    print("-" * 64)
    print(" >> WebMail (login aqui)   : http://localhost:5000")
    print(" Claves + jku (atacante)   : http://localhost:9000")
    print("=" * 64)
    print(" (Ctrl+C para cortar)")

    # El atacante (9000) se comparte: si ya lo levanto el otro lanzador, se reusa.
    if puerto_libre(9000):
        threading.Thread(target=correr, args=(atacante.app, 9000), daemon=True).start()
    else:
        print(" [i] Atacante ya corriendo en 9000, lo reuso.")
    threading.Thread(target=correr, args=(servidor_vulnerable.app, 5000), daemon=True).start()

    time.sleep(1.2)
    webbrowser.open("http://localhost:5000/")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nListo, cortado.")
