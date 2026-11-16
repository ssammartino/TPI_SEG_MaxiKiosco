# Caso 3 — JWT · JKU Header Injection (INSTANCIA SOLUCIONADA)

Versión **corregida** de la WebMail del Caso 3. Resiste exactamente el mismo
ataque de inyección de clave pública vía `jku`.

## La corrección en una frase

`verificar_token()` **ignora** los headers `jku` y `jwk` del token y valida la
firma **siempre con la clave pública del propio servidor**, fijando el
algoritmo a `RS256`. Como el atacante no tiene la clave privada del servidor,
su firma nunca valida y el token forjado se rechaza.

```python
# vulnerable: si hay jku, baja la clave de esa URL (la elige el token)
# solucionado:
def verificar_token(token):
    return jwt.decode(token, SERVER_PUBLIC_PEM, algorithms=["RS256"])
```

| | vulnerable | solucionado (este caso) |
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

Levanta el servidor seguro (5001) y la máquina del atacante (9000: página de
**claves** + JWKS), y abre el navegador en la WebMail segura.

## Demo con Burp Suite (el mismo ataque, pero REBOTA)

Es idéntico al flujo del caso vulnerable: armás el **mismo** token malicioso en
Burp (con **JWT Editor**) y lo enviás. La diferencia es el resultado.

**Preparación (una sola vez):** en http://localhost:9000 copiá la **clave
privada del atacante** e importala en **JWT Editor → Keys**.

1. **Login** — entrá a http://localhost:5001 y logueate como `pedro / pedro123`.
   Interceptá con Burp y capturá el JWT.
2. **Al Repeater** — mandá la request de `/inbox` al **Repeater**.
3. **Modificá** el JWT en la pestaña **JSON Web Token**: payload
   `"user":"admin"` y agregá al header la línea `jku` (de la página de claves).
4. **Sign** con la clave del atacante → token re-firmado.
5. **Send**: el servidor seguro responde `Token invalido` → **ataque
   bloqueado**. Ignora el `jku` y valida con **su propia clave**, que el
   atacante no tiene.

Para ver el contraste, corré también el lanzador del caso **vulnerable**
(`Caso 3 - Vul`, puerto 5000): ambos comparten el atacante de 9000, así que
podés mandar **el mismo token** a `:5000` (roba) y a `:5001` (rechaza).

## ¿Qué hay en cada archivo?

```
lanzar.py                un comando: levanta todo y abre la WebMail segura
servidor_seguro.py       WebMail corregida (puerto 5001): login + bandeja
atacante.py              la misma máquina del atacante (9000): claves + JWKS
templates/claves.html    3ª página: claves privada/pública + línea jku
templates/login.html     login de la WebMail (donde capturás con Burp)
templates/inbox.html     bandeja de entrada
```

> ⚠️ Uso exclusivamente educativo, en entornos locales y propios.
