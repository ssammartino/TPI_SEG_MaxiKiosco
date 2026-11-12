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
DNS_PORT = 5354  # debe coincidir con el puerto con el que corriste dns_rebinding_server.py
DOMAIN = "midominio.test"
APP_PORT = 5000  # puerto de vulnerable_app.py


def resolve(domain: str) -> str:
    """Hace UNA consulta DNS tipo A contra nuestro servidor de juguete y
    devuelve la IP que respondio, como string."""

    # dns.message.make_query arma un mensaje de consulta DNS valido (los
    # mismos bytes crudos que construimos a mano en el servidor, pero aca
    # la libreria dnspython nos hace el trabajo sucio). "A" = queremos un
    # registro de direccion IPv4.
    query = dns.message.make_query(domain, "A")

    # dns.query.udp manda esa consulta por UDP al servidor/puerto indicado
    # y espera la respuesta (hasta "timeout" segundos). Devuelve un objeto
    # "response" ya parseado (dnspython se encarga de interpretar los bytes
    # crudos de la respuesta por nosotros).
    response = dns.query.udp(query, DNS_SERVER, port=DNS_PORT, timeout=3)

    # response.answer es una lista de "RRsets" (conjuntos de registros de
    # recursos); cada rrset puede tener uno o mas "items" (en nuestro caso,
    # siempre va a haber un solo rrset con un solo item: la IP que
    # respondio el servidor).
    for rrset in response.answer:
        for item in rrset.items:
            return item.address  # item.address es la IP como string, ej "127.0.0.1"

    raise RuntimeError("sin respuesta DNS")


def es_ip_privada(ip_str: str) -> bool:
    # ipaddress.ip_address() convierte el string en un objeto IP de Python,
    # que ya trae estas propiedades calculadas (no hay que parsear nada a mano).
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    # is_private: rangos como 10.x, 192.168.x, etc.
    # is_loopback: 127.0.0.0/8 (localhost)
    # is_link_local: 169.254.x.x (direcciones auto-asignadas, incluye el
    #                metadata service de algunos clouds: 169.254.169.254)
    # is_reserved: rangos reservados por IANA que no deberian usarse en internet


def main():
    print(f"Simulando una app que valida '{DOMAIN}' y despues hace fetch...\n")

    # --- Paso 1: la app "valida" el hostname resolviendo el DNS ---
    # Esta es la PRIMERA consulta DNS. Nuestro servidor de juguete, al ver
    # que es la primera vez que este cliente pregunta, responde con la IP
    # publica benigna (ver dns_rebinding_server.py).
    ip_validacion = resolve(DOMAIN)
    print(f"[validacion] {DOMAIN} resuelve a {ip_validacion}")
    if es_ip_privada(ip_validacion):
        print("[validacion] BLOQUEADO: la IP es privada/loopback")
        return
    print("[validacion] OK, la IP es publica -> se permite continuar\n")

    # --- Gap de tiempo: el TTL del registro DNS es bajo (5s) a proposito,
    #     para forzar que cualquier resolucion posterior pida de nuevo ---
    # En una app real este "gap" no es un sleep explicito: es el tiempo que
    # tarda la app en terminar de validar y efectivamente hacer el pedido
    # HTTP (que puede incluir cola de tareas, reintentos, otra logica,
    # etc). Aca lo simulamos con un time.sleep() para que se note clarito.
    print("Esperando a que venza el TTL del registro DNS (6s)...\n")
    time.sleep(6)

    # --- Paso 2: el cliente HTTP vuelve a resolver el DNS al conectar.
    #     En una app real esto lo hace la libreria HTTP sola, sin que el
    #     desarrollador lo note; aca lo hacemos explicito para la demo ---
    # Esta es la SEGUNDA consulta DNS de este mismo cliente. Nuestro
    # servidor de juguete, al verla, ya responde con la IP interna real
    # (ver query_count en dns_rebinding_server.py).
    ip_fetch = resolve(DOMAIN)
    print(f"[fetch]      {DOMAIN} resuelve ahora a {ip_fetch}")

    if ip_fetch != ip_validacion:
        print("[fetch]      ⚠️  La IP cambio entre la validacion y el fetch (rebinding)\n")

    # Hacemos el "fetch real" contra la IP que resolvio en este momento
    # (no contra la que habiamos "validado" antes): esto es exactamente lo
    # que haria el cliente HTTP de una app vulnerable, que resuelve DNS por
    # su cuenta al momento de conectar.
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
