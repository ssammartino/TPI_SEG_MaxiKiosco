"""Demuestra localmente cómo una respuesta DNS puede cambiar entre consultas."""

# dnspython consulta el DNS; ipaddress clasifica la IP; requests hace el fetch.
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
    """Consulta el registro A del dominio al DNS local."""
    query = dns.message.make_query(domain, "A")
    response = dns.query.udp(query, DNS_SERVER, port=DNS_PORT, timeout=3)
    for rrset in response.answer:
        for item in rrset.items:
            return item.address

    raise RuntimeError("sin respuesta DNS")


def es_ip_privada(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    # El resultado es True si la dirección es privada o de uso especial.
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def main():
    print(f"Simulando una app que valida '{DOMAIN}' y despues hace fetch...\n")

    # Primera consulta: el servidor devuelve una IP pública de ejemplo.
    ip_validacion = resolve(DOMAIN)
    print(f"[validacion] {DOMAIN} resuelve a {ip_validacion}")
    if es_ip_privada(ip_validacion):
        print("[validacion] BLOQUEADO: la IP es privada/loopback")
        return
    print("[validacion] OK, la IP es publica -> se permite continuar\n")

    # Pausa para ilustrar el TTL corto de la respuesta DNS.
    print("Esperando a que venza el TTL del registro DNS (6s)...\n")
    time.sleep(6)

    # Segunda consulta: el servidor responde ahora con otra IP.
    ip_fetch = resolve(DOMAIN)
    print(f"[fetch]      {DOMAIN} resuelve ahora a {ip_fetch}")

    if ip_fetch != ip_validacion:
        print("[fetch]      ⚠️  La IP cambio entre la validacion y el fetch (rebinding)\n")

    # El fetch usa la segunda respuesta DNS, no la IP aprobada en el primer paso.
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
