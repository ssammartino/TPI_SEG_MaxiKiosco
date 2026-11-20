# Caso 3 — JWT · JKU Header Injection (INSTANCIA VULNERABLE)

## Arranque

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python lanzar.py
```

## Qué modificar en el token

- **Payload:** `"user": "admin"`
- **Header (línea a agregar):** `"jku": "http://localhost:9000/jwks.json"`

## Direcciones

- **Servidor (WebMail):** http://localhost:5000
- **Servidor de claves (atacante):** http://localhost:9000
