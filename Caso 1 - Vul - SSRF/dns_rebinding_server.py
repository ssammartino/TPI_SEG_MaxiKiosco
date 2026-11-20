"""Servidor DNS de laboratorio que alterna su respuesta para la demo."""

# socket recibe/envía UDP; struct codifica números para el paquete DNS;
# sys lee dominio y puerto opcionales desde la terminal.
import socket
import sys
import struct

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "midominio.test"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5354
PUBLIC_IP = "93.184.216.34"
REBIND_IP = "127.0.0.1"

# Contador de consultas por IP del cliente.
query_count = {}


def build_response(query: bytes, ip: str) -> bytes:
    """Construye una respuesta DNS con un registro A."""
    # Conserva el ID y la pregunta; el resto del encabezado indica una respuesta.
    transaction_id = query[:2]
    flags = b"\x81\x80"
    qdcount = query[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    question = query[12:]

    # Añade un registro A: IPv4, TTL de 5 s y la dirección en formato binario.
    answer = (
        b"\xc0\x0c"
        + b"\x00\x01"
        + b"\x00\x01"
        + struct.pack(">I", 5)
        + b"\x00\x04"
        + socket.inet_aton(ip)
    )
    return header + question + answer


def main():
    # Este servidor de laboratorio escucha en todas las interfaces.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    print(f"Escuchando consultas DNS para '{DOMAIN}' en 127.0.0.1:{PORT}...")
    print(f"1ra consulta -> {PUBLIC_IP} | 2da en adelante -> {REBIND_IP}")

    while True:
        # Atiende la consulta y lleva la cuenta por cliente para alternar IP.
        data, addr = sock.recvfrom(512)
        client_ip = addr[0]
        query_count[client_ip] = query_count.get(client_ip, 0) + 1

        # Primera respuesta pública; las siguientes, loopback.
        ip = PUBLIC_IP if query_count[client_ip] == 1 else REBIND_IP
        print(f"Consulta #{query_count[client_ip]} de {addr} -> respondiendo {ip}")

        sock.sendto(build_response(data, ip), addr)


if __name__ == "__main__":
    main()
