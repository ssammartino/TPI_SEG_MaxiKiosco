"""
dns_rebinding_demo.py
----------------------
Simula el patron de codigo vulnerable que hace posible un DNS rebinding:

    1. Resuelve el hostname -> valida que la IP no sea privada/loopback.
    2. (tiempo despues, con otra resolucion de DNS) hace el fetch real.

Si el DNS responde distinto en el paso 1 y el paso 2 (porque el atacante
controla ese DNS y cambia la respuesta con un TTL bajo), el validador vio
una IP publica pero el fetch real pega contra la IP interna.

Requisitos:
    pip install dnspython requests
    1) Correr vulnerable_app.py (puerto 5000)
    2) Correr dns_rebinding_server.py midominio.test  (puerto 5353)
    3) Correr este script
"""

import time
import dns.message
import dns.query
import ipaddress
import requests

DNS_SERVER = "127.0.0.1"
DNS_PORT = 5354
DOMAIN = "midominio.test"
APP_PORT = 5000  # puerto de vulnerable_app.py


def resolve(domain: str) -> str:
    query = dns.message.make_query(domain, "A")
    response = dns.query.udp(query, DNS_SERVER, port=DNS_PORT, timeout=3)
    for rrset in response.answer:
        for item in rrset.items:
            return item.address
    raise RuntimeError("sin respuesta DNS")


def es_ip_privada(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def main():
    print(f"Simulando una app que valida '{DOMAIN}' y despues hace fetch...\n")

    # --- Paso 1: la app "valida" el hostname resolviendo el DNS ---
    ip_validacion = resolve(DOMAIN)
    print(f"[validacion] {DOMAIN} resuelve a {ip_validacion}")
    if es_ip_privada(ip_validacion):
        print("[validacion] BLOQUEADO: la IP es privada/loopback")
        return
    print("[validacion] OK, la IP es publica -> se permite continuar\n")

    # --- Gap de tiempo: el TTL del registro DNS es bajo (5s) a proposito,
    #     para forzar que cualquier resolucion posterior pida de nuevo ---
    print("Esperando a que venza el TTL del registro DNS (6s)...\n")
    time.sleep(6)

    # --- Paso 2: el cliente HTTP vuelve a resolver el DNS al conectar.
    #     En una app real esto lo hace la libreria HTTP sola, sin que el
    #     desarrollador lo note; aca lo hacemos explicito para la demo ---
    ip_fetch = resolve(DOMAIN)
    print(f"[fetch]      {DOMAIN} resuelve ahora a {ip_fetch}")

    if ip_fetch != ip_validacion:
        print("[fetch]      ⚠️  La IP cambio entre la validacion y el fetch (rebinding)\n")

    # Hacemos el "fetch real" contra la IP que resolvio en este momento
    url = f"http://{ip_fetch}:{APP_PORT}/internal/secret"
    try:
        resp = requests.get(url, timeout=3)
        print(f"Fetch real a {url}")
        print(f"Status: {resp.status_code}")
        print("Body:")
        print(resp.text)
    except Exception as e:
        print(f"Error en el fetch: {e}")


if __name__ == "__main__":
    main()
