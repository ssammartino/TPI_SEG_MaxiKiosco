## Archivos
### Paso 1: Regex validation
- `vulnerable_app.py` — API Flask con `/fetch?url=` protegida por un filtro
  **ingenuo** (regex sobre el string de la URL). Es el 1er paso, no valida nada. Ni contra el DNS
- `attack_demo.py` — ataca `vulnerable_app.py` con representaciones
  alternativas de `127.0.0.1` que el regex no reconoce.

### Paso 2: 
- `fixed_app.py` — misma funcionalidad, con las 4 mitigaciones aplicadas.
- `dns_rebinding_server.py` — servidor DNS de juguete que ilustra el
  concepto de DNS rebinding (requiere configuración extra, ver abajo).

## 1. Levantar la app vulnerable

```bash
pip install flask requests
python vulnerable_app.py
```
