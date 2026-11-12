"""
run_with_fake_dns.py
---------------------
Arranca vulnerable_app_resolve_check.py pero redirige la resolucion DNS de
UN dominio especifico (midominio.test) hacia nuestro servidor DNS de
juguete (dns_rebinding_server.py) -- sin tocar la configuracion de red del
sistema operativo, sin hosts file, sin permisos de administrador.

Como funciona: toda resolucion de nombre en Python (incluida la que hace
`requests` por dentro, via urllib3) pasa por socket.getaddrinfo(). Esta
funcion la "parcheamos" en memoria (monkeypatch) SOLO para este proceso:
si el hostname pedido es el dominio de la demo, le preguntamos a nuestro
servidor DNS falso; para cualquier otro hostname, usamos la funcion
original sin modificar nada.

Requisitos:
    pip install flask requests dnspython
    1) Correr: python dns_rebinding_server.py midominio.test   (puerto 5354)
    2) Correr: python run_with_fake_dns.py                      (puerto 5000)
    3) Abrir el navegador en http://localhost:5000 y pegar en el form:
       http://midominio.test:5000/internal/secret
"""

import socket
import dns.message
import dns.query

DOMINIO_FALSO = "midominio.test"
DNS_SERVER = "127.0.0.1"
DNS_PORT = 5354  # debe coincidir con el puerto de dns_rebinding_server.py

# Guardamos una referencia a la funcion ORIGINAL antes de reemplazarla, para
# poder seguir usandola con cualquier otro hostname que no sea el nuestro.
_getaddrinfo_original = socket.getaddrinfo


def resolver_via_dns_falso(host: str) -> str:
    """Le pregunta directamente a dns_rebinding_server.py por este host,
    igual que hace dns_rebinding_demo.py, pero ahora en el medio del
    proceso real de la app vulnerable."""
    query = dns.message.make_query(host, "A")
    response = dns.query.udp(query, DNS_SERVER, port=DNS_PORT, timeout=3)
    for rrset in response.answer:
        for item in rrset.items:
            return item.address
    raise socket.gaierror(f"no se pudo resolver {host} via DNS falso")


def getaddrinfo_parcheado(host, port=0, family=0, type=0, proto=0, flags=0):
    if host == DOMINIO_FALSO:
        ip = resolver_via_dns_falso(host)
        # getaddrinfo normalmente devuelve una LISTA de tuplas con esta forma:
        # (familia, tipo_socket, protocolo, nombre_canonico, (ip, puerto)).
        # Armamos una entrada minima con la IP que nos dio el DNS falso,
        # para que requests/urllib3 se conecten a ESA IP.
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    # Para cualquier otro hostname (ej. "localhost", "api.github.com", etc.)
    # usamos la resolucion real de siempre, sin tocar nada.
    return _getaddrinfo_original(host, port, family, type, proto, flags)


# Reemplazamos la funcion global ANTES de importar la app: asi, cuando la
# app (y requests/urllib3 dentro de ella) llamen a socket.getaddrinfo,
# van a usar esta version parcheada.
socket.getaddrinfo = getaddrinfo_parcheado

from vulnerable_app_resolve_check import app  # noqa: E402 (import despues del parche, a proposito)

if __name__ == "__main__":
    print(f"DNS de '{DOMINIO_FALSO}' redirigido a {DNS_SERVER}:{DNS_PORT} (resto de dominios sin cambios)")
    app.run(port=5000)
