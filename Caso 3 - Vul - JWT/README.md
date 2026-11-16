# Caso 3 — JWT · JKU Header Injection (INSTANCIA VULNERABLE)

Demo educativa (Python + Flask) de una vulnerabilidad de **inyección de clave
pública en JWT**: el servidor confía en el header `jku` del token para decidir
**desde dónde se baja la clave pública** con la que valida la firma.

## La vulnerabilidad en una frase

Para validar la firma de un JWT, el servidor **debería** usar siempre su clave
de confianza. Esta versión, en cambio, mira el header `jku` del propio token y
**descarga la clave pública desde la URL que indique el token**. Si el atacante
pone ahí la URL de *su* clave, el servidor valida con la clave del atacante y
acepta un token falso → **bypass de autenticación y escalada a admin**.

```
token.header.jku  ──►  http://localhost:9000/jwks.json   (servidor del atacante)
                        el servidor VÍCTIMA se baja esa clave y valida con ella
```

La única diferencia entre vulnerable y solucionado está en `verificar_token()`:

| | vulnerable (este caso) | solucionado |
|---|---|---|
| Si el token trae `jku` | baja la clave de esa URL y valida con ella | se ignora |
| Clave usada para validar | la que diga el token | siempre la del servidor |

## Arranque

```bash
pip install -r requirements.txt
python lanzar.py
```

> ¿No tenés el comando `pip`? Usá un entorno virtual (dentro, `pip` ya funciona):
> ```bash
> python3 -m venv venv
> source venv/bin/activate
> pip install -r requirements.txt
> python lanzar.py
> ```

`lanzar.py` levanta el servidor vulnerable (5000) y la máquina del atacante
(9000: página de **claves** + JWKS), y abre el navegador en la WebMail.

La página http://localhost:9000 muestra el **par de claves del atacante** (para
firmar en Burp) y la **línea `jku`** lista para copiar al header del token.

## Demo con Burp Suite (vos hacés el ataque, paso a paso)

Todo el ataque lo hacés **vos** en Burp. Necesitás la extensión **JWT Editor**.

**Preparación (una sola vez):** en http://localhost:9000 copiá la **clave
privada del atacante** (sección 1) y, en Burp → **JWT Editor → Keys →
New RSA Key**, pegala y guardala. Es el par de la clave que el servidor se baja
del `jku`, por eso tu firma va a validar.

1. **Login** — entrá a http://localhost:5000 y logueate como `pedro / pedro123`.
   Interceptá con Burp la petición al **iniciar sesión** y capturá el JWT.
2. **Al Repeater** — mandá la request de `/inbox` (la que lleva
   `Authorization: Bearer <token>`) al **Repeater**.
3. **Modificá el JWT** — en la pestaña **JSON Web Token** del Repeater:
   - cambiá el payload a `"user": "admin"`,
   - agregá al header la línea `jku` (copiala de la sección 3 de la página de
     claves): `"jku": "http://localhost:9000/jwks.json"`.
4. **Generá el token nuevo** — apretá **Sign**, elegí la clave del atacante.
   El token queda re-firmado con firma válida.
5. **Reenviá** — **Send**. El servidor te devuelve la **bandeja del admin**
   aunque nunca pusiste su contraseña.

Cuando mandás ese token, el servidor vulnerable ve el `jku`, **se baja la clave
del atacante** y valida con ella. Esa es la falla. Para el contraste, mandá el
**mismo** token contra el servidor seguro (`Caso 3 - Sol`, puerto 5001):
responde `Token invalido`.

## ¿Qué hay en cada archivo?

```
lanzar.py                 un comando: levanta todo y abre la WebMail
servidor_vulnerable.py    WebMail vulnerable (puerto 5000): login + bandeja
atacante.py               máquina del atacante (9000): página de claves + JWKS
templates/claves.html     3ª página: claves privada/pública + línea jku
templates/login.html      login de la WebMail (donde capturás con Burp)
templates/inbox.html      bandeja de entrada
```

Usuarios en memoria: `pedro / pedro123` (rol user) y `admin / admin123`
(bandeja con los correos "sensibles" que se roban).

> ⚠️ Uso exclusivamente educativo, en entornos locales y propios.
