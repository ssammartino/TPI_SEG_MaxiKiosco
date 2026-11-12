# Lab: SSRF + Bypass de validación de URL

Laboratorio para clase sobre SSRF. Todo corre en `localhost`; no hace falta ni se debe apuntar nada a infraestructura real de terceros.

## Mapa de archivos: qué resuelve cada uno (y qué NO)

| Archivo | Qué es | Qué resuelve/valida | Qué NO resuelve (el bug) |
| --- | --- | --- | --- |
| `vulnerable_app.py` | Sitio vulnerable, con form web | Nada por DNS — compara el **string** de la URL contra una lista de patrones | No mira la IP real a la que apunta la URL, solo el texto |
| `attack_demo.py` | Script de ataque | — | Prueba bypasses de texto contra `vulnerable_app.py` (hex, octal, decimal, DNS público) |
| `fixed_app.py` | Sitio reforzado, con el mismo form web | Resuelve y valida la IP real, fija la conexión a esa IP, usa allowlist y no sigue redirects | Requiere mantener la allowlist y el aislamiento de red como defensa en profundidad |
| `vulnerable_app_resolve_check.py` | Sitio "a medio camino" | Resuelve el host y valida la IP real (como `fixed_app.py`) | Pero el fetch real vuelve a resolver el DNS por su cuenta → queda abierto a DNS rebinding |
| `dns_rebinding_server.py` | DNS falso de laboratorio | Responde IP pública en la 1ª consulta de un cliente, y `127.0.0.1` de ahí en más | No es un DNS real, solo sirve para esta demo |
| `dns_rebinding_demo.py` | Cliente de prueba aislado | Habla directo con `dns_rebinding_server.py` por UDP, simula validar+fetch, y hace el fetch real contra `vulnerable_app.py` | No pasa por el código de ninguna de las apps — es un script standalone para ver el mecanismo del rebinding sin nada más en el medio |
| `dns_rebinding_demo_simulado.py` | Cliente de prueba sin red | Simula el mismo patrón que `dns_rebinding_demo.py`, pero con una función de Python en memoria en vez de sockets UDP reales | Alternativa para cuando el firewall/antivirus bloquea el puerto UDP del DNS falso |
| `run_with_fake_dns.py` | "Pegamento" para la demo end-to-end | Redirige, solo para el dominio de prueba, la resolución DNS de todo el proceso hacia `dns_rebinding_server.py` | No toca la configuración de red del sistema ni necesita permisos de administrador |

---

## Escenario A — Bypass del filtro regex (lo más simple)

No hay DNS truqueado acá: el problema es que `vulnerable_app.py` valida **texto**, no la IP real.

1. `pip install flask requests`
2. Terminal 1: `python vulnerable_app.py` → queda en `http://localhost:5000`
3. Terminal 2: `python attack_demo.py`
4. También podés probarlo a mano en el navegador: entrá a `http://localhost:5000`, pegá en el form `http://127-0-0-1.nip.io:5000/internal/secret` (o `http://localtest.me:5000/internal/secret`) y apretá "Vista previa". Vas a ver el `.env` falso.

Por qué funciona: el filtro busca el substring `"127.0.0.1"` o `"localhost"` en la URL. Si la URL está escrita de otra forma (hex, octal, guiones de nip.io) pero igual **resuelve** a `127.0.0.1` cuando `requests.get()` la usa, el filtro nunca se enteró.

Nota sobre los payloads `[fragil]` de `attack_demo.py` (hex/octal/decimal): dependen de que el sistema operativo interprete esa notación numérica como IP al resolver el host. En Windows, `socket.getaddrinfo()` es estricto y los trata como nombre de dominio → da error de DNS en vez de 403. Esa inconsistencia entre sistemas es justamente parte de la lección.

---

## Escenario B — DNS rebinding, versión conceptual (sin red real)

Para explicar el mecanismo sin depender de sockets, firewalls ni puertos:

1. `pip install flask requests`
2. Terminal 1: `python vulnerable_app.py`
3. Terminal 2: `python dns_rebinding_demo_simulado.py`

Este script simula un "resolver" con una función de Python: la primera vez que la consulta devuelve una IP pública (pasa la validación), la segunda devuelve `127.0.0.1`. El fetch final sí es real, contra `vulnerable_app.py`. Sirve para ver la lógica del bug sin nada de infraestructura de por medio.

---

## Escenario C — DNS rebinding con un DNS falso de verdad (script aislado)

Mismo concepto que el Escenario B, pero con un servidor DNS real (aunque de juguete) hablando por UDP, para mostrar que el truco funciona contra una resolución DNS de verdad y no es solo un cuento.

1. `pip install flask requests dnspython`
2. Terminal 1: `python vulnerable_app.py`
3. Terminal 2: `python dns_rebinding_server.py midominio.test` → escucha en `127.0.0.1:5354` (puerto normal, sin privilegios de administrador)
4. Terminal 3: `python dns_rebinding_demo.py`

Este script le pregunta dos veces a `dns_rebinding_server.py` (primero "valida", espera el TTL, "resuelve" de nuevo) y después hace el fetch real contra `vulnerable_app.py` con la segunda IP. Es un script standalone: no pasa por el código de validación de ninguna de las apps, solo demuestra el mecanismo DNS en sí.

**Si te tira timeout en Windows:** normalmente es el firewall bloqueando el UDP entrante. Revisá si apareció el popup de Windows Defender Firewall pidiendo permiso para `python.exe`, o directamente usá el Escenario B, que no depende de la red.

---

## Escenario D — DNS rebinding contra el sitio vulnerable de verdad (end-to-end)

Este es el que prueba el ataque pasando por el código real de una app, no por un script aislado. Usa `vulnerable_app_resolve_check.py`, que a diferencia de `vulnerable_app.py` **sí** valida la IP resuelta — pero cae en la trampa de volver a resolver el DNS al hacer el fetch real.

1. `pip install flask requests dnspython`
2. Terminal 1: `python dns_rebinding_server.py midominio.test` → puerto `5354`
3. Terminal 2: `python run_with_fake_dns.py` → **no** corras `vulnerable_app_resolve_check.py` directo; este wrapper es el que redirige la resolución de `midominio.test` hacia el DNS falso antes de levantar la app. Queda en `http://localhost:5000`
4. Abrí el navegador en `http://localhost:5000`
5. Pegá en el form: `http://midominio.test:5000/internal/secret` y apretá "Vista previa"

Qué pasa adentro:

- La validación resuelve `midominio.test` (1ª consulta al DNS falso) → IP pública → pasa el chequeo.
- El fetch real, dentro de `requests.get()`, vuelve a resolver el mismo hostname (2ª consulta) → el DNS falso ahora responde `127.0.0.1`.
- Resultado: la página muestra el `.env` filtrado, aunque la validación de IP nunca vio nada sospechoso.

No hace falta esperar el TTL de 5 segundos: `dns_rebinding_server.py` cuenta las consultas por IP del cliente (no por tiempo), así que las dos resoluciones del mismo request ya le alcanzan para responder distinto.

---

## Mitigaciones (`fixed_app.py`)

| # | Mitigación | Dónde está en el código |
| --- | --- | --- |
| 1 | Resolver DNS, validar la **IP real** y conectar a esa misma IP | `resolve_and_validate_ip()` valida; el adaptador de `request_validated_url()` fija el destino de la conexión y conserva el hostname para HTTP/TLS |
| 2 | **Allowlist** en vez de denylist | `ALLOWED_HOSTS` |
| 3 | Sin redirects automáticos | `requests.get(url, allow_redirects=False)` |
| 4 | Aislamiento de red del servicio fetcher | Medida de infraestructura, no de código (ver docstring del archivo) |

**Importante:** `fixed_app.py` reutiliza la IP validada como destino TCP de la conexión HTTP. El nombre original se conserva para el encabezado `Host` y para la validación TLS en HTTPS; de esta forma `requests` no hace una segunda resolución para decidir a qué IP conectarse. El aislamiento de red del servicio y la allowlist siguen siendo defensas en profundidad recomendadas.