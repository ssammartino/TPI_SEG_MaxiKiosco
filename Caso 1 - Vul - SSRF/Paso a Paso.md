# Paso a paso: SSRF y DNS rebinding

Esta guía recorre los ejemplos del laboratorio en orden: primero el bypass del filtro de URL, después DNS rebinding aislado, luego la prueba end-to-end y, por último, la aplicación reforzada.

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

Usa una terminal por cada proceso. Para detener un servidor, vuelve a su terminal y pulsa `Ctrl+C`. No dejes dos aplicaciones intentando escuchar en el mismo puerto.

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

## 2. DNS rebinding aislado

Este paso muestra el cambio de respuesta DNS, pero **no ejecuta la validación dentro de la app**: el cliente de prueba simula esa secuencia por su cuenta.

### Qué hacen los archivos

- [dns_rebinding_server.py](./dns_rebinding_server.py) es un DNS de laboratorio. Para cada IP de cliente, da una IP pública de ejemplo en la primera consulta y `127.0.0.1` en las siguientes.
- [dns_rebinding_demo.py](./dns_rebinding_demo.py) consulta dos veces a ese DNS, simula validar la primera respuesta y luego hace una petición HTTP a la segunda.

### Pasos

1. En la Terminal 1, levanta la app que contiene el recurso local de demostración:
   ```powershell
   python vulnerable_app.py
   ```
2. En la Terminal 2, inicia el DNS falso:
   ```powershell
   python dns_rebinding_server.py midominio.test
   ```
3. En la Terminal 3, ejecuta el cliente:
   ```powershell
   python dns_rebinding_demo.py
   ```

Deberías ver que la primera resolución devuelve `93.184.216.34`, la segunda `127.0.0.1` y el fetch final obtiene la respuesta del recurso local. El script espera unos segundos, pero este servidor cambia la respuesta por número de consulta, no porque mida el vencimiento del TTL.

## 3. DNS rebinding end-to-end

Este es el escenario que pasa por el código de validación de una app. [vulnerable_app_resolve_check.py](./vulnerable_app_resolve_check.py) resuelve el host y valida la IP una vez, pero luego `requests.get()` vuelve a resolver el nombre para conectarse. El DNS cambiante puede hacer que la segunda resolución vaya a `127.0.0.1`.

[run_with_fake_dns.py](./run_with_fake_dns.py) conecta la app al DNS de laboratorio para `midominio.test`, sin cambiar la configuración DNS de Windows.

### Pasos

1. Detén cualquier app o DNS de pruebas anterior con `Ctrl+C`. En particular, no dejes `vulnerable_app.py` usando el puerto 5000.
2. En la Terminal 1:
   ```powershell
   python dns_rebinding_server.py midominio.test
   ```
3. En la Terminal 2:
   ```powershell
   python run_with_fake_dns.py
   ```
   Debe indicar que redirige `midominio.test` a `127.0.0.1:5354` y que Flask escucha en el puerto 5000.
4. Abre `http://localhost:5000` y pega en el formulario:
   ```text
   http://midominio.test:5000/internal/secret
   ```

En la terminal del DNS deberías ver primero una respuesta a `93.184.216.34` y luego otra a `127.0.0.1`. La página mostrará el secreto ficticio si el rebinding se completa.

**Importante:** reinicia `dns_rebinding_server.py` antes de repetir la prueba. Mantiene un contador por IP de cliente; tras la primera consulta responde `127.0.0.1` en las siguientes. Si la validación ya recibe `127.0.0.1`, comprueba que reiniciaste el DNS. Si aparece `NameResolutionError` para `midominio.test`, probablemente la petición la está atendiendo `vulnerable_app.py` y no el wrapper: detén la app directa y ejecuta `run_with_fake_dns.py`.

## Aclaraciones sobre la demo

### DNS rebinding aislado vs. end-to-end

| Aislado | End-to-end |
| --- | --- |
| `dns_rebinding_demo.py` hace las dos consultas DNS y simula la validación en el propio script. | `run_with_fake_dns.py` inicia `vulnerable_app_resolve_check.py`, y la app hace la validación y el fetch. |
| `vulnerable_app.py` solo sirve el recurso local `/internal/secret` que el script consulta. | Se prueba el error real: la app valida una resolución y `requests` hace otra para conectarse. |
| Sirve para entender el cambio de respuesta sin pasar por la app que valida. | Sirve para demostrar que ese patrón de la app puede ser vulnerable. |

### ¿Se saltea Google DNS o Cloudflare?

No. Son **resolvers recursivos**: buscan la respuesta DNS para quien pregunta. El DNS **autoritativo** es el que administra las respuestas de un dominio; el dueño de un dominio elige qué proveedor lo aloja, y ese proveedor puede atender muchos dominios.

En una situación real, Google DNS o Cloudflare buscarían la respuesta en la jerarquía DNS hasta llegar al servidor autoritativo del dominio y devolverían lo que este publica, sujeto a caché y controles. No hace falta evadir ni controlar el resolver público. La respuesta DNS tampoco garantiza que una IP sea segura para una aplicación: solo indica a qué dirección se asocia el nombre.

El servidor de este laboratorio es distinto: `dns_rebinding_server.py` responde por UDP en tu máquina. Los scripts le consultan directamente, y `run_with_fake_dns.py` redirige solo las resoluciones de `midominio.test` dentro de ese proceso. No cambia la configuración DNS de Windows ni suplanta a Google o Cloudflare.

### ¿Por qué la respuesta cambia enseguida y no espera cinco segundos?

El servidor de laboratorio lleva un contador por IP del cliente, no un reloj. La primera consulta recibe `93.184.216.34`; la segunda y las siguientes reciben `127.0.0.1`. El TTL de 5 segundos va dentro de la respuesta, pero el escenario end-to-end no espera a que venza: el wrapper pregunta directamente al servidor falso durante cada resolución.

En una petición end-to-end, la app pregunta una vez para validar y `requests` pregunta otra vez para conectarse. Por eso el cambio ocurre inmediatamente. `dns_rebinding_demo.py` incluye una pausa para ilustrar el TTL, pero el servidor de juguete sigue cambiando la respuesta por número de consulta.

### ¿Por qué luego bloquea `127.0.0.1`?

La primera petición normalmente hace las consultas #1 y #2: la validación recibe la IP pública y el fetch recibe `127.0.0.1`, por lo que aparece el secreto ficticio. En una petición posterior, la validación ya es la consulta #3 y recibe `127.0.0.1`; entonces la app la bloquea.

Para repetir la demostración, detén `dns_rebinding_server.py` con `Ctrl+C` y vuelve a iniciarlo para reiniciar el contador. No es una prohibición que se active por tiempo.

## 4. Página reforzada (solución)

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
| [dns_rebinding_demo.py](./dns_rebinding_demo.py) | Demostración aislada de cambio de IP y fetch. |
| [vulnerable_app_resolve_check.py](./vulnerable_app_resolve_check.py) | Valida una resolución, pero vuelve a resolver al hacer el fetch. |
| [run_with_fake_dns.py](./run_with_fake_dns.py) | Inicia la app anterior con el DNS de laboratorio. |
| [fixed_app.py](<../Caso 1 - Sol - SSRF/fixed_app.py>) | Página reforzada en el puerto 5001; conecta a la IP validada y no sigue redirects. |

El [README.md](./README.md) menciona `dns_rebinding_demo_simulado.py`, pero ese archivo no está en esta carpeta. No necesitas ese script para seguir los escenarios de esta guía.
