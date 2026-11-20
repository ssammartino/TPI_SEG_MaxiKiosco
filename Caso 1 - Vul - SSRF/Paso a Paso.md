# Paso a paso: SSRF y DNS rebinding

Esta guía recorre la prueba del filtro vulnerable, la demostración end-to-end de DNS rebinding y, por último, la aplicación reforzada.

Todo está pensado para ejecutarse en la propia máquina. Los secretos que aparecen son ficticios. No apuntes estas pruebas a sistemas de terceros.

## Preparación

Abre PowerShell en la carpeta `Caso 1 - Vul - SSRF`:

```powershell
cd "D:\UTN\Cuarto Año\SEG\TPI_SEG_MaxiKiosco\Caso 1 - Vul - SSRF"
```

Instala las dependencias necesarias:

```powershell
python -m pip install flask requests dnspython
```

### Qué hace cada librería

| Librería o módulo | Para qué se usa |
| --- | --- |
| `flask` | Levanta la web, recibe los formularios y arma las respuestas HTML/JSON. |
| `requests` | Hace desde Python las peticiones HTTP a la URL ingresada. |
| `dnspython` (`dns`) | Construye y envía consultas DNS al servidor de laboratorio. |
| `socket` | Resuelve nombres de host y maneja la comunicación de red. |
| `ipaddress` | Convierte texto en una IP y permite reconocer direcciones privadas o especiales. |
| `urllib.parse` | Separa las partes de una URL, por ejemplo su host. |
| `re` | Busca patrones de texto en la URL de la versión vulnerable. |
| `struct`, `sys` | Prepara datos binarios DNS y lee argumentos de consola. |
| `urllib3` | Maneja conexiones HTTP bajo `requests`; la solución lo usa para fijar la IP. |

`flask`, `requests` y `dnspython` se instalan con `pip`. Los demás son módulos de Python o dependencias instaladas junto con `requests`.

Usa una terminal por cada proceso. Para detener un servidor, vuelve a su terminal y pulsa `Ctrl+C`. No dejes dos aplicaciones intentando escuchar en el mismo puerto.

## Guion sugerido para la exposición (12-15 minutos)

### 1. Introducir SSRF

Puedes empezar así: **“SSRF ocurre cuando una aplicación hace una petición desde su servidor a una URL que le indicó el usuario. Si no controla bien el destino, el servidor podría consultar recursos internos a los que el usuario no llega directamente.”**

Aclara que el navegador entrega el enlace a la aplicación, pero es el servidor quien hace la petición. En este proyecto los datos internos son ficticios y las pruebas se ejecutan en localhost.

### 2. Mostrar el primer problema: filtro por texto

Abre dos terminales en `Caso 1 - Vul - SSRF`:

1. Terminal 1:
   ```powershell
   python vulnerable_app.py
   ```
2. Terminal 2:
   ```powershell
   python attack_demo.py
   ```

En la salida, señala el control con `127.0.0.1`, que debería dar `403`, y luego un caso que obtenga `200` y muestre el recurso ficticio. Explica que esta primera parte demuestra que buscar texto en una URL no equivale a comprobar su destino real. Algunos casos pueden depender de internet o del sistema operativo.

### 3. Introducir DNS rebinding

Explica la idea antes de ejecutar la segunda prueba: **“Un nombre de dominio puede resolver a una IP y, en otra consulta, a una distinta. DNS rebinding aprovecha ese cambio cuando una aplicación valida una respuesta, pero luego se conecta usando otra.”**

### 4. Ejecutar y mostrar el DNS rebinding end-to-end

Detén `vulnerable_app.py` con `Ctrl+C`. En `Caso 1 - Vul - SSRF`, usa dos terminales:

1. Terminal 1: inicia el DNS de laboratorio:
   ```powershell
   python dns_rebinding_server.py midominio.test
   ```
2. Terminal 2: inicia la app con el puente:
   ```powershell
   python bridge_app_dns.py
   ```
3. Abre `http://localhost:5000` y envía:
   ```text
   http://midominio.test:5000/internal/secret
   ```

Muestra la terminal del DNS: la primera respuesta es `93.184.216.34` y la segunda `127.0.0.1`. La página recibe el contenido ficticio de `/internal/secret`.

### 5. Explicar qué ocurrió y qué hacen el DNS autoritativo y el puente

Usa esta secuencia sencilla:

1. El navegador manda el formulario a Flask; el navegador no resuelve `midominio.test`.
2. `validar_host()` consulta DNS. La primera respuesta parece pública y pasa la validación.
3. `requests.get()` recibe el nombre original y lo resuelve otra vez para conectarse.
4. El DNS devuelve `127.0.0.1`; la app no vuelve a validar ni fija la IP anterior. Entonces el servidor Flask envía una petición HTTP a sí mismo y alcanza `/internal/secret`.

Aclara los nombres:

- **DNS autoritativo:** en una situación real, es el servidor que publica las respuestas DNS de un dominio. Quien controla el dominio puede cambiar esas respuestas. El resolver recursivo de la empresa o del proveedor consulta al autoritativo y puede guardar respuestas en caché.
- **`dns_rebinding_server.py`:** servidor local de laboratorio que simula respuestas cambiantes. No reproduce toda la jerarquía DNS real; cambia la respuesta por número de consulta para que la demo sea predecible.
- **`bridge_app_dns.py` (puente/adaptador):** no es el DNS autoritativo. Intercepta, solo dentro de este proceso y para `midominio.test`, las consultas que hace la app y las dirige al servidor local. No cambia la configuración DNS de Windows.

Puedes resumir la diferencia así: **“En la demo, el puente consulta directamente al DNS local y el cambio es inmediato. En la vida real, el servidor de la aplicación usa su resolver DNS habitual, que consulta al autoritativo; las cachés y el TTL pueden hacer que el cambio no sea inmediato ni garantizado.”**

### 6. Presentar la defensa específica contra DNS rebinding

La defensa es **conectarse a la misma IP que se validó**, en lugar de volver a resolver el nombre al hacer la petición. Si hay una redirección, también debe bloquearse o validarse de nuevo. Así, aunque DNS cambie la respuesta después, la conexión no cambia silenciosamente de destino.

### 7. Mostrar la solución completa en `fixed_app.py`

Detén la app y el DNS local con `Ctrl+C`. Desde `Caso 1 - Sol - SSRF`, inicia la versión reforzada:

```powershell
python "..\Caso 1 - Sol - SSRF\fixed_app.py"
```

Abre `http://localhost:5001` y prueba `http://127.0.0.1:5001/internal/secret`: la allowlist lo rechaza. Explica que `fixed_app.py` reúne defensas para ambos problemas: permite solo hosts conocidos, valida sus IP, conecta a la IP validada y no sigue redirecciones automáticamente. Si tienes internet, puedes mostrar una URL permitida como `https://jsonplaceholder.typicode.com/todos/1`.

**Cierre sugerido:** “No alcanza con filtrar cómo está escrita una URL. Hay que limitar los hosts, validar la dirección real y asegurar que la conexión use esa misma dirección.”

## 1. App vulnerable y prueba de bypass

### Qué hace `vulnerable_app.py`

[vulnerable_app.py](./vulnerable_app.py) levanta una web en `http://localhost:5000`. Su formulario está en `/preview` y también ofrece un endpoint `/fetch` para pruebas automatizadas.

La app busca patrones como `127.0.0.1` y `localhost` en el **texto** de la URL. No comprueba a qué dirección IP resuelve realmente el host. Si la URL evita esos patrones pero termina resolviendo a la propia máquina, el servidor puede hacer una petición a un recurso interno: eso es el problema de SSRF que ilustra este ejemplo.

### Qué hace `attack_demo.py`

[attack_demo.py](./attack_demo.py) manda distintas URL al endpoint `/fetch` para comparar:

- Una dirección literal `127.0.0.1`, que el filtro debería bloquear con `403`.
- Otras formas de escribir o nombrar la dirección local, que el filtro de texto podría no reconocer.

Un `200` indica que la petición llegó a algún recurso. Un error de resolución DNS no significa que el filtro la haya bloqueado: puede ser una variante numérica que Windows no reconoce. Las pruebas con `nip.io` o `localtest.me` requieren internet y dependen de esos servicios públicos de DNS.

### Pasos

1. En la Terminal 1:
   ```powershell
   python vulnerable_app.py
   ```
2. En la Terminal 2:
   ```powershell
   python attack_demo.py
   ```
3. También puedes abrir `http://localhost:5000` y probar en el formulario:
   ```text
   http://localtest.me:5000/internal/secret
   ```

La respuesta interna es un texto de demostración, no credenciales reales.

## 2. DNS rebinding end-to-end

Este es el escenario que pasa por el código de validación de una app. [vulnerable_app_resolve_check.py](./vulnerable_app_resolve_check.py) resuelve el host y valida la IP una vez, pero luego `requests.get()` vuelve a resolver el nombre para conectarse. La app no reutiliza la IP que validó; el DNS cambiante puede hacer que la segunda resolución vaya a `127.0.0.1`.

[bridge_app_dns.py](./bridge_app_dns.py) es el **puente DNS** de la demo, no el servidor DNS falso. Guarda la función original `socket.getaddrinfo` y la reemplaza dentro de ese proceso: solo cuando la app pide resolver `midominio.test`, el puente envía una consulta DNS por UDP a `127.0.0.1:5354`. Para cualquier otro nombre, usa la función original. Instala este reemplazo antes de importar la app, para que tanto su validación como `requests` pasen por el puente. Así se prueba el flujo sin cambiar la configuración DNS de Windows.

En simple: la validación pregunta “¿a qué IP apunta este nombre?” y aprueba la primera respuesta. Después `requests` recibe el **nombre**, no la IP aprobada, y vuelve a preguntar para conectarse. Si DNS responde distinto, la conexión puede terminar en otra IP. Es como comprobar una dirección en un mapa y, al enviar algo, volver a consultar el nombre y recibir una dirección diferente.

### Pasos

1. Detén cualquier app o DNS de pruebas anterior con `Ctrl+C`. En particular, no dejes `vulnerable_app.py` usando el puerto 5000.
2. En la Terminal 1:
   ```powershell
   python dns_rebinding_server.py midominio.test
   ```
3. En la Terminal 2:
   ```powershell
   python bridge_app_dns.py
   ```
   Debe indicar que redirige `midominio.test` a `127.0.0.1:5354` y que Flask escucha en el puerto 5000.
4. Abre `http://localhost:5000` y pega en el formulario:
   ```text
   http://midominio.test:5000/internal/secret
   ```

En la terminal del DNS deberías ver primero una respuesta a `93.184.216.34` y luego otra a `127.0.0.1`. La página mostrará el secreto ficticio si el rebinding se completa.

**Importante:** reinicia `dns_rebinding_server.py` antes de repetir la prueba. Mantiene un contador por IP de cliente; tras la primera consulta responde `127.0.0.1` en las siguientes. Si la validación ya recibe `127.0.0.1`, comprueba que reiniciaste el DNS. Si aparece `NameResolutionError` para `midominio.test`, probablemente la petición la está atendiendo `vulnerable_app.py` y no el wrapper: detén la app directa y ejecuta `bridge_app_dns.py`.

## Aclaraciones sobre la demo

### ¿Se saltea Google DNS o Cloudflare?

No. Son **resolvers recursivos**: buscan la respuesta DNS para quien pregunta. El DNS **autoritativo** es el que administra las respuestas de un dominio; el dueño de un dominio elige qué proveedor lo aloja, y ese proveedor puede atender muchos dominios.

En una situación real, Google DNS o Cloudflare buscarían la respuesta en la jerarquía DNS hasta llegar al servidor autoritativo del dominio y devolverían lo que este publica, sujeto a caché y controles. No hace falta evadir ni controlar el resolver público. La respuesta DNS tampoco garantiza que una IP sea segura para una aplicación: solo indica a qué dirección se asocia el nombre.

El servidor de este laboratorio es distinto: `dns_rebinding_server.py` responde por UDP en tu máquina. Los scripts le consultan directamente, y `bridge_app_dns.py` redirige solo las resoluciones de `midominio.test` dentro de ese proceso. No cambia la configuración DNS de Windows ni suplanta a Google o Cloudflare.

### ¿Quién pregunta y cuál es el flujo end-to-end?

En esta prueba, el navegador **no resuelve `midominio.test`**. El navegador solo se comunica con la app por `http://localhost:5000`; es la app Flask la que intenta resolver el dominio que escribiste en el formulario.

1. El navegador envía a Flask el formulario con `http://midominio.test:5000/internal/secret`.
2. Flask extrae el hostname `midominio.test` y lo valida con `socket.getaddrinfo()`.
3. La función `validar_host()` llama a `socket.getaddrinfo()` para validar la IP. Como la app se inició con `bridge_app_dns.py`, esa llamada pasa por el puente y sale por UDP hacia el DNS falso local. La primera respuesta es `93.184.216.34`, que pasa la validación.
4. Flask continúa con `requests.get()` para hacer el fetch. Como recibe la URL con el nombre `midominio.test` y no reutiliza la IP validada, `requests` necesita resolverlo otra vez para abrir la conexión. Esa segunda llamada también pasa por el puente y vuelve a consultar el DNS falso.
5. Es la segunda consulta del DNS de laboratorio, así que responde `127.0.0.1`. La app se conecta a `127.0.0.1:5000`, que es el propio servidor Flask.
6. Flask recibe esa petición en `/internal/secret`, devuelve el secreto ficticio a `requests`, y la página muestra el resultado al navegador.

En resumen: **el navegador habla con Flask; Flask hace las dos consultas DNS y luego el fetch**. La validación y la conexión ocurren dentro del servidor, no en el navegador.

### End-to-end local vs. vida real

| En este laboratorio, todo es local | En un caso real |
| --- | --- |
| `dns_rebinding_server.py` corre en tu máquina como DNS falso, en `127.0.0.1:5354`. | El DNS autoritativo controlado por quien posee el dominio está en otro equipo o servicio. |
| `bridge_app_dns.py` levanta la app Flask y redirige, dentro de ese proceso, las consultas de `midominio.test` al DNS local. **No es el DNS falso.** | La app usa el resolver DNS configurado en su sistema o infraestructura. Ese resolver consulta la jerarquía DNS y llega al DNS autoritativo del dominio. |
| El navegador envía el formulario a Flask en `localhost:5000`. La app pregunta directamente al DNS local: primero recibe una IP pública de ejemplo y luego `127.0.0.1`. El fetch a `127.0.0.1:5000` vuelve a la misma app y alcanza `/internal/secret`. | El navegador envía la URL a la app alojada en un servidor. La app hace las resoluciones desde ese servidor; si acaba conectándose a una IP privada, el intento de acceso interno también sale desde ese servidor, no desde el navegador del usuario. |
| El servidor falso cambia la respuesta por número de consulta, así que el resultado es inmediato y predecible. | Las cachés y el TTL pueden hacer que ambas resoluciones reciban la misma IP. El cambio no está garantizado; depende del resolver, de sus cachés y de que la app no reutilice la IP validada. |

En una situación real, el dueño de un dominio puede administrar sus respuestas DNS autoritativas. El resolver recursivo —por ejemplo, el de una empresa, Google o Cloudflare— no se saltea: busca la respuesta del dominio y se la devuelve a la app. El laboratorio reemplaza ese recorrido por una consulta directa al servidor local para poder mostrar el flujo sin configurar un dominio público ni depender de las cachés reales.

### Ejemplo para contar en la exposición

Imagina que una empresa ofrece una función para generar una vista previa de enlaces. Una persona envía un enlace de un dominio que controla. El servidor de la empresa consulta el DNS y valida la primera IP recibida, que parece pública. Cuando el servidor HTTP va a conectarse, el nombre puede resolverse a otra IP, esta vez de la red privada de la empresa. Si la aplicación no comprueba ni fija esa segunda dirección, el propio servidor podría enviar una petición a un panel interno que no debería estar disponible para el usuario.

La diferencia con el laboratorio es que aquí todo ocurre en la misma computadora: `bridge_app_dns.py` manda las consultas de prueba directamente a `dns_rebinding_server.py`, que cambia la respuesta por número de consulta. En la vida real, el DNS autoritativo del dominio publica las respuestas y el resolver recursivo de la infraestructura las consulta y puede guardarlas en caché. Por eso el cambio no necesariamente ocurre de inmediato ni en cada ejecución: depende del TTL, la caché y de cómo la aplicación resuelve y reutiliza las IP.

Para decirlo durante la exposición: **“En la demo, el cambio de IP está preparado para ser inmediato y local. En un caso real, quien controla el dominio cambia su respuesta DNS; el servidor de la víctima hace las consultas y, si no fija la IP validada, puede terminar enviando la petición a un servicio interno.”**

### ¿Por qué la respuesta cambia enseguida y no espera cinco segundos?

El servidor de laboratorio lleva un contador por IP del cliente, no un reloj. La primera consulta recibe `93.184.216.34`; la segunda y las siguientes reciben `127.0.0.1`. El TTL de 5 segundos va dentro de la respuesta, pero el escenario end-to-end no espera a que venza: el wrapper pregunta directamente al servidor falso durante cada resolución.

En una petición end-to-end, la app pregunta una vez para validar y `requests` pregunta otra vez para conectarse. El servidor de laboratorio cambia la respuesta por número de consulta, no cuando vence el TTL; por eso el cambio es inmediato en esta demostración.

### ¿Por qué luego bloquea `127.0.0.1`?

La primera petición normalmente hace las consultas #1 y #2: la validación recibe la IP pública y el fetch recibe `127.0.0.1`, por lo que aparece el secreto ficticio. En una petición posterior, la validación ya es la consulta #3 y recibe `127.0.0.1`; entonces la app la bloquea.

Para repetir la demostración, detén `dns_rebinding_server.py` con `Ctrl+C` y vuelve a iniciarlo para reiniciar el contador. No es una prohibición que se active por tiempo.

## 3. Página reforzada (solución)

[fixed_app.py](<../Caso 1 - Sol - SSRF/fixed_app.py>) es la versión reforzada y escucha en `http://localhost:5001`, por lo que puede correr junto a una app en el puerto 5000.

Aplica varias defensas: usa una allowlist de hosts permitidos, valida las IP resueltas, conecta a la misma IP que validó y no sigue redirects automáticamente.

### Pasos

1. Desde la carpeta `Caso 1 - Sol - SSRF`, ejecuta:
   ```powershell
   python fixed_app.py
   ```
   O desde la carpeta de la versión vulnerable:
   ```powershell
   python "..\Caso 1 - Sol - SSRF\fixed_app.py"
   ```
2. Abre `http://localhost:5001`.
3. Prueba en el formulario una URL local:
   ```text
   http://127.0.0.1:5001/internal/secret
   ```
   Debe rechazarla porque `127.0.0.1` no está en la allowlist.
4. Para probar una petición permitida, puedes usar:
   ```text
   https://jsonplaceholder.typicode.com/todos/1
   ```
   Este caso necesita conexión a internet. Si no tienes conectividad, un error de red no demuestra que la validación haya fallado.

### Qué queda cubierto y qué sigue recomendado

El adaptador de `fixed_app.py` fija la conexión TCP a la IP que pasó la validación y conserva el hostname original para el encabezado `Host` y la validación TLS. Así evita que el cliente HTTP vuelva a elegir una IP mediante una segunda resolución DNS. El aislamiento de red del servicio y la allowlist siguen siendo defensas en profundidad recomendadas.

En estas rutas de fetch, el DNS cambiante de la demo no debería llevar la conexión a `127.0.0.1`: la app valida la IP y conecta a esa misma. La allowlist también rechaza `midominio.test`, que no es uno de los hosts permitidos. Esto describe las defensas de esos endpoints, no una garantía sobre otros endpoints o servicios del servidor.

## Mapa rápido de archivos

| Archivo | Función |
| --- | --- |
| [vulnerable_app.py](./vulnerable_app.py) | Web vulnerable al SSRF por filtro textual. |
| [attack_demo.py](./attack_demo.py) | Pruebas automatizadas del bypass del filtro. |
| [dns_rebinding_server.py](./dns_rebinding_server.py) | DNS falso local para la demostración. |
| [vulnerable_app_resolve_check.py](./vulnerable_app_resolve_check.py) | Valida una resolución, pero vuelve a resolver al hacer el fetch. |
| [bridge_app_dns.py](./bridge_app_dns.py) | Inicia la app y hace de puente: dirige solo las consultas de `midominio.test` al DNS falso local. |
| [fixed_app.py](<../Caso 1 - Sol - SSRF/fixed_app.py>) | Página reforzada en el puerto 5001; conecta a la IP validada y no sigue redirects. |

