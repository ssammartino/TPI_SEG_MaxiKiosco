# Demo: JWT JKU Header Injection (clave pública inyectada)

Proyecto educativo que muestra, con Python + Flask, una vulnerabilidad de
**inyección de clave pública** en la validación de JWT (header `jku`), junto
a su versión corregida.

## La vulnerabilidad

Al validar la firma de un JWT, un servidor **debe** usar su clave de confianza
configurada del lado servidor. La versión vulnerable, en cambio, confía en el
header `jku` del propio token: baja la clave pública desde la URL que indica el
token y valida con ella. Un atacante entonces:

1. genera su propio par de claves,
2. hostea su clave pública como JWKS,
3. forja un token (`user: admin`) firmado con su clave privada y con un `jku`
   apuntando a su JWKS,
4. el servidor baja esa clave, la firma "valida", y acepta el token →
   **bypass de autenticación y escalada de privilegios**.

La única diferencia entre vulnerable y corregido está en `verificar_token()`.

| | vulnerable | corregido |
|---|---|---|
| Si el token trae `jku` | baja la clave de esa URL y valida con ella | se ignora |
| Clave usada para validar | la que diga el token | siempre la del servidor |

El token legítimo lleva solo `{"alg":"RS256","typ":"JWT"}` (sin `jku`); el del
atacante agrega el `jku`. Payload: `{"user": "..."}` (sin `exp`, sin `role`).

## Estructura

```
seg/
├── vulnerable/app.py          # servidor VULNERABLE  (puerto 5000)
├── seguro/app.py              # servidor CORREGIDO    (puerto 5001)
├── atacante/
│   ├── generar_claves.py      # paso 1: claves + jwks.json del atacante
│   ├── servidor_jwks.py       # paso 2: hostea el JWKS (puerto 9000)
│   └── forjar_token.py        # paso 3: forja el token user=admin con jku
└── requirements.txt
```

Usuarios en memoria: `pedro / pedro123` (rol user) y `admin / admin123`
(bandeja con los correos "sensibles" que se roban).

## Instalación

```bash
cd /Users/pedro/Desktop/seg
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Demo del ataque (contra el VULNERABLE)

Abrí 3 terminales (todas con el venv activado).

**Terminal 1 — servidor vulnerable:**

```bash
python vulnerable/app.py
```

**Terminal 2 — infra del atacante:**

```bash
python atacante/generar_claves.py
python atacante/servidor_jwks.py
```

**Terminal 3 — forjar y atacar:**

```bash
python atacante/forjar_token.py
```

Ese último script imprime el token y el `curl` listo para copiar. Al pegarlo
verás la bandeja del **admin** aunque nunca pusiste su contraseña:

```bash
curl -s http://localhost:5000/inbox -H "Authorization: Bearer <TOKEN_FORJADO>"
```

## Demo de que el CORREGIDO resiste

```bash
python seguro/app.py          # puerto 5001
```

El mismo token forjado contra el 5001 devuelve `Token invalido` (la firma no
valida con la clave del servidor):

```bash
curl -s http://localhost:5001/inbox -H "Authorization: Bearer <TOKEN_FORJADO>"
```

## Opción jwt.io / Burp (para la expo)

En vez de `forjar_token.py` podés armar el token en https://jwt.io:
header `{"alg":"RS256","typ":"JWT","jku":"http://localhost:9000/jwks.json"}`,
payload `{"user":"admin"}`, y pegás tu clave privada/pública del atacante para
que lo firme. Después, con **Burp Repeater**, tomás la request a `/inbox` y
reemplazás el `Authorization: Bearer ...` por el token forjado.

> ⚠️ Uso exclusivamente educativo, en entornos locales y propios.
