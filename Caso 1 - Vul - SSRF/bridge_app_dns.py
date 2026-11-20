"""Redirige el DNS de midominio.test al servidor local para la demo."""

# socket proporciona el resolver que se reemplaza; dnspython consulta el DNS falso.
import socket
import dns.message
import dns.query

DOMINIO_FALSO = "midominio.test"
DNS_SERVER = "127.0.0.1"
DNS_PORT = 5354  # debe coincidir con el puerto de dns_rebinding_server.py

# Conserva la resolución original para cualquier otro hostname.
_getaddrinfo_original = socket.getaddrinfo


def resolver_via_dns_falso(host: str) -> str:
    """Consulta el DNS local y devuelve la IP recibida."""
    # A solicita una dirección IPv4; la respuesta se consulta por UDP.
    query = dns.message.make_query(host, "A")
    response = dns.query.udp(query, DNS_SERVER, port=DNS_PORT, timeout=3)
    for rrset in response.answer:
        for item in rrset.items:
            return item.address
    raise socket.gaierror(f"no se pudo resolver {host} via DNS falso")


def getaddrinfo_parcheado(host, port=0, family=0, type=0, proto=0, flags=0):
    if host == DOMINIO_FALSO:
        ip = resolver_via_dns_falso(host)
        # Devuelve el formato que esperan socket y el cliente HTTP.
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    return _getaddrinfo_original(host, port, family, type, proto, flags)


# Parche local al proceso: solo afecta este dominio y esta ejecución.
socket.getaddrinfo = getaddrinfo_parcheado

from vulnerable_app_resolve_check import app  # noqa: E402

if __name__ == "__main__":
    print(f"DNS de '{DOMINIO_FALSO}' redirigido a {DNS_SERVER}:{DNS_PORT} (resto de dominios sin cambios)")
    app.run(port=5000)
