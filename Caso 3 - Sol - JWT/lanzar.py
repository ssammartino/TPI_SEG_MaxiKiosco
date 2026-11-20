"""
LANZADOR — un solo comando levanta toda la demo del Caso 3 (SOLUCIONADA).

    python lanzar.py

Arranca, en segundo plano:
  - el servidor SOLUCIONADO   -> http://localhost:5001  (WebMail segura)
  - la maquina del ATACANTE   -> http://localhost:9000  (claves + JWKS)

y abre el navegador en la WebMail. Armas el MISMO token malicioso con Burp y,
al enviarlo contra :5001, el servidor lo RECHAZA (ignora el jku y valida con su
propia clave).

Tip para la expo: si tambien tenes corriendo el lanzador VULNERABLE (5000),
ambos comparten el atacante de 9000 y podes mandar el mismo token a los dos
puertos para comparar (5000 roba, 5001 rechaza).

Para cortar: Ctrl+C.
"""
import socket
import threading
import time
import webbrowser

from werkzeug.serving import make_server

import atacante
import servidor_seguro


def puerto_libre(puerto):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", puerto)) != 0


def correr(app, puerto):
    make_server("0.0.0.0", puerto, app, threaded=True).serve_forever()


if __name__ == "__main__":
    print("=" * 64)
    print(" CASO 3 - JWT JKU Injection  |  INSTANCIA SOLUCIONADA")
    print("-" * 64)
    print(" >> WebMail segura (login): http://localhost:5001")
    print(" Claves + jku (atacante)  : http://localhost:9000")
    print("=" * 64)
    print(" (Ctrl+C para cortar)")

    # El atacante (9000) se comparte con el lanzador vulnerable si ya corre.
    if puerto_libre(9000):
        threading.Thread(target=correr, args=(atacante.app, 9000), daemon=True).start()
    else:
        print(" [i] Atacante ya corriendo en 9000, lo reuso.")
    threading.Thread(target=correr, args=(servidor_seguro.app, 5001), daemon=True).start()

    time.sleep(1.2)
    webbrowser.open("http://localhost:5001/")   # WebMail segura (login)
    webbrowser.open("http://localhost:9000/")   # pagina del atacante (claves + jku)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nListo, cortado.")
