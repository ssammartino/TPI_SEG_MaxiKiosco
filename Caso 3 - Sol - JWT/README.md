# Caso 3 — JWT · JKU Header Injection (INSTANCIA SOLUCIONADA)

## Arranque

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python lanzar.py
```

## Qué modificar en el token

El mismo ataque que en el caso vulnerable, pero acá el token **se rechaza**:

- **Payload:** `"user": "admin"`
- **Header (línea a agregar):** `"jku": "http://localhost:9000/jwks.json"`

## Direcciones

- **Servidor seguro (WebMail):** http://localhost:5001
- **Servidor de claves (atacante):** http://localhost:9000
