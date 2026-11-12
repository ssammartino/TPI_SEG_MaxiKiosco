# Caso 2 (Seguro) — CSP con Nonce + strict-dynamic + Escape de Input

## Resumen

`fixed_app.py` corre en `http://localhost:5003` y corrige las dos causas
raíz del Caso 2 Vulnerable:

1. **El XSS reflejado en sí mismo** (causa raíz real).
2. **La CSP débil por whitelist de dominios** (la mitigación que fallaba).

---

## Ejecutar

```bash
pip install flask
python fixed_app.py
```

Abrir: `http://localhost:5003`

---

## Corrección 1 — Escape del input (la que realmente importa)

```python
page = render_template_string(PAGE_TEMPLATE, q=q, ...)
```

`render_template_string` usa el motor Jinja2 con **autoescape activado**
(comportamiento por defecto en Flask). El template tiene `{{ q }}`, nunca
`{{ q | safe }}`. Esto significa que si `q` contiene `<script>`, Jinja2 lo
convierte a `&lt;script&gt;` antes de insertarlo en el HTML — el navegador
lo muestra como **texto visible**, nunca lo interpreta como una etiqueta
nueva.

> Esta es la corrección más importante de las dos. Sin ella, un atacante
> podría seguir intentando bypasses de CSP eternamente. Con el escape
> correcto, ni siquiera hace falta CSP para frenar el XSS — la CSP es una
> **segunda capa de defensa** (defense in depth), no la primera.

## Corrección 2 — CSP con nonce + `'strict-dynamic'`

```
default-src 'self';
script-src 'nonce-<ALEATORIO_POR_REQUEST>' 'strict-dynamic' 'sha256-<HASH>' 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
connect-src 'self';
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
```

- **`nonce-...`**: se genera con `secrets.token_urlsafe(16)` en **cada
  request**, server-side. Solo un `<script nonce="ESE_VALOR_EXACTO">`
  ejecuta. Un atacante que inyecta HTML en `q` no puede adivinar el nonce
  de la respuesta porque se genera después de que su input ya fue
  procesado, y es criptográficamente aleatorio.
- **`'strict-dynamic'`**: en navegadores que lo soportan, hace que la
  whitelist de dominios (`https://cdnjs...`, `https://www.google.com`)
  **se ignore por completo** para scripts — lo único que importa es el
  nonce. Esto es intencional: en vez de mantener una lista de "dominios
  de confianza" (que, como vimos, pueden tener gadgets), confiamos en
  que *el servidor* decide qué scripts corren, vía nonce.
- **`sha256-...`**: para el único script inline fijo de la página (no
  depende del input del usuario), se calcula su hash SHA-256 y se agrega
  a la whitelist. Si alguien modifica ese script (o inyecta uno con
  contenido distinto), el hash no coincide y no ejecuta.
- **Sin `'unsafe-inline'` ni `'unsafe-eval'`** en `script-src`: ningún
  `<script>` sin nonce/hash corre, y ninguna conversión string→código
  (`eval`, `new Function(...)`, `setTimeout("string")`) está permitida.

---

## Por qué los bypasses del Caso Vulnerable NO funcionan acá

### Intento: XSS reflejado simple
```
http://localhost:5003/?q=<script>alert(1)</script>
```
**No llega ni a evaluarse por CSP** — Jinja2 ya lo convirtió en texto
(`&lt;script&gt;alert(1)&lt;/script&gt;`) antes de que el navegador vea el
HTML. No hay ninguna etiqueta `<script>` real en el DOM.

### Intento: AngularJS desde cdnjs
Aunque de alguna forma el atacante lograra que se inyecte un
`<script src="https://cdnjs.cloudflare.com/...">` real en el HTML (cosa
que el escape de `q` ya impide), ese script **no tiene el nonce correcto**
→ la CSP lo bloquea antes de descargarlo siquiera. Y aunque se descargara,
no hay `'unsafe-eval'`, así que el gadget `constructor.constructor(...)`
tampoco podría ejecutar.

### Intento: JSONP desde google.com
Mismo razonamiento: sin el nonce exacto (que cambia en cada request y es
impredecible), cualquier `<script src="https://www.google.com/...">`
inyectado es bloqueado directamente por la CSP, sin importar que el
dominio "suene confiable".

---

## Comparación de cabeceras (lado a lado)

| | Vulnerable (5002) | Segura (5003) |
|---|---|---|
| Escape de `q` | ❌ No | ✅ Sí (Jinja2 autoescape) |
| Estrategia CSP | Whitelist de dominios | Nonce + `'strict-dynamic'` |
| `'unsafe-eval'` | ✅ Presente (simulando misconfig real) | ❌ Ausente |
| `'unsafe-inline'` en `script-src` | ❌ Ausente | ❌ Ausente |
| Nonce por request | No aplica | ✅ Sí, aleatorio |
| Vulnerable a bypass CDN/JSONP | ✅ Sí | ❌ No |

---

## Lección de la demo

La CSP por whitelist de dominios depende de que **todo lo que esos
dominios sirvan sea confiable**, algo que en la práctica no se puede
garantizar (CDNs públicos alojan miles de librerías, algunas con sandbox
escapes conocidos; endpoints JSONP ejecutan callbacks arbitrarios). La
estrategia de **nonce + `'strict-dynamic'`** traslada la confianza del
"dominio de origen" al "¿lo autorizó el servidor en esta respuesta
específica?", eliminando esa superficie de ataque — pero **nada de esto
reemplaza la necesidad de escapar correctamente el input del usuario**,
que sigue siendo la primera línea de defensa.
