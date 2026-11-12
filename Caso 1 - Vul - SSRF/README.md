# Lab: SSRF + Bypass de validación de URL

Laboratorio autocontenido para clase. Todo corre en `localhost`, no se
necesita ni se debe apuntar nada a infraestructura real de terceros.

## Archivos

- `vulnerable_app.py` — API Flask con `/fetch?url=` protegida por un filtro
  **ingenuo** (regex sobre el string de la URL).
- `attack_demo.py` — ataca `vulnerable_app.py` con representaciones
  alternativas de `127.0.0.1` que el regex no reconoce.
- `fixed_app.py` — misma funcionalidad, con las 4 mitigaciones aplicadas.
- `dns_rebinding_server.py` — servidor DNS de juguete que ilustra el
  concepto de DNS rebinding (requiere configuración extra, ver abajo).

## 1. Levantar la app vulnerable

```bash
pip install flask requests
python vulnerable_app.py
```

Probá a mano que el filtro "funciona":

```bash
curl "http://localhost:5000/fetch?url=http://127.0.0.1:5000/internal/secret"
# -> 403 "URL bloqueada por el filtro de seguridad"
```

## 2. Ejecutar el ataque

En otra terminal:

```bash
python attack_demo.py
```

Vas a ver que variantes como `http://0x7f000001/`, `http://2130706433/`,
`http://0177.0.0.1/` o la IPv6 `[::1]` **pasan el filtro** y devuelven el
contenido de `/internal/secret`, porque:

- El filtro compara **substrings** (`"127.0.0.1"`, `"localhost"`, rangos
  RFC1918 escritos en decimal con puntos) contra el string de la URL.
- Nunca se resuelve ni se normaliza la URL a una IP real: Python
  (`requests` → `urllib3` → el sistema operativo) sí sabe interpretar
  hexadecimal, octal, decimal de 32 bits e IPv6, pero el validador no.

### ⚠️ Nota sobre Windows / portabilidad de los payloads

Los payloads `0x7f000001`, `2130706433`, `0177.0.0.1`, etc. dependen de que
el **resolver del sistema operativo** interprete esos strings como notación
numérica alternativa de una IP. Eso lo hacen `curl`, los navegadores y a
veces la libc de Linux — pero **`socket.getaddrinfo()` en Windows es
estricto**: si el string no es `a.b.c.d` exacto, lo trata como nombre de
dominio y lo manda a DNS real, lo que da `NameResolutionError`
(`[Errno 11001] getaddrinfo failed`) en vez del 403 del filtro.

Esto **no es un error tuyo ni del lab**: es exactamente el fenómeno de
"parsers inconsistentes" que la clase busca mostrar — el mismo payload
puede evadir el filtro en un entorno y fallar en otro por razones que no
tienen nada que ver con el filtro en sí.

Para una demo que **funcione en cualquier SO sin tocar nada en tu máquina**
(ni hosts file, ni permisos de administrador), usá estos dos payloads de
`attack_demo.py`, que resuelven vía **DNS público real**:

- `http://127-0-0-1.nip.io:5000/internal/secret` — `nip.io` es un servicio
  público que resuelve cualquier subdominio con una IP escrita con
  guiones a esa misma IP. El string no contiene "127.0.0.1" (tiene
  guiones, no puntos), así que el regex no lo detecta, y la resolución es
  DNS normal, por lo que funciona igual en Windows/Mac/Linux.
- `http://localtest.me:5000/internal/secret` — otro dominio público que
  siempre resuelve a `127.0.0.1`. Ni siquiera necesita truco de formato:
  simplemente no contiene ningún substring bloqueado.

Solo necesitás que la máquina donde corrés `attack_demo.py` tenga
internet para resolver esos dominios (el fetch real sigue siendo 100%
local, contra tu Flask en `localhost:5000`).

Si preferís una demo 100% offline, la alternativa es agregar una entrada
en el archivo de hosts (`C:\Windows\System32\drivers\etc\hosts` en
Windows, `/etc/hosts` en Linux/Mac) apuntando un dominio inventado a
`127.0.0.1`, pero eso requiere permisos de administrador — por eso las
opciones de arriba son más prácticas para mostrar en clase.

### DNS rebinding (concepto)

El otro vector de la consigna es más sutil: un atacante registra un
dominio propio (`evil.test`) cuyo servidor DNS:

1. Responde con una IP pública benigna la **primera vez** que la app lo
   resuelve (pasa la validación "¿es privada?").
2. Responde con `127.0.0.1` (o una IP interna) en resoluciones
   posteriores — con un TTL bajo para forzar que el cliente HTTP vuelva a
   resolver.

Si la app valida el hostname resolviendo el DNS una vez, y **el cliente
HTTP hace su propia resolución por separado** al momento del fetch real,
el atacante gana la carrera: la validación vio la IP pública, el fetch
real pega contra `127.0.0.1`.

`dns_rebinding_server.py` incluye una implementación mínima de este
comportamiento (primera consulta = IP pública, siguientes = `127.0.0.1`)
para que lo muestres en clase. Montarlo de punta a punta requiere delegar
un dominio real a ese servidor o configurar un resolver local
(`dnsmasq`/`/etc/resolv.conf` apuntando a `127.0.0.1`), así que es más
una pieza para explicar el mecanismo que para "correr y listo" — vale la
pena mostrarlo como diagrama/trace en el pizarrón si el setup de red del
aula no lo permite.

## 3. Mitigaciones (`fixed_app.py`)

| # | Mitigación | Dónde está en el código |
|---|---|---|
| 1 | Resolver DNS y validar la **IP real**, no el string | `resolve_and_validate_ip()` usa `socket.getaddrinfo` + `ipaddress` (`is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_multicast`, `is_unspecified`) |
| 2 | **Allowlist** en vez de denylist | `ALLOWED_HOSTS`, se rechaza cualquier host no listado |
| 3 | Sin redirects automáticos | `requests.get(url, allow_redirects=False)` + corte si la respuesta es redirect |
| 4 | Aislamiento de red del servicio fetcher | Es una medida de **infraestructura**, no de código: correr el servicio en una subred sin rutas a `169.254.169.254` (metadata cloud) ni a rangos RFC1918 internos. Anotado en el docstring del archivo. |

Nota sobre el punto 1: esto también cierra el DNS rebinding **siempre
que la validación y el fetch usen la misma resolución** (resolver una
vez, reusar esa IP para conectar — por ejemplo pasándole la IP ya
resuelta al cliente HTTP en vez de dejar que vuelva a resolver el
hostname). Si tu cliente HTTP vuelve a resolver el DNS en el momento de
conectar, seguís expuesto aunque hayas "validado" antes.

```bash
python fixed_app.py
python attack_demo.py  # cambiando TARGET a http://localhost:5001/fetch
```

Vas a ver que todas las variantes devuelven 403, y que incluso para un
host de la allowlist, si resolviera a una IP privada, también se
bloquearía.
