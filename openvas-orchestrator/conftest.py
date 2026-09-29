"""Pytest bootstrap: hace que `import main` funcione igual que dentro del
contenedor Docker de este servicio (donde el Dockerfile copia main.py a
/app, WORKDIR es /app y PYTHONPATH=/app), sin necesitar Docker ni
variables de entorno especiales para correr los tests localmente o en CI
(`pytest` desde la raiz del repo o desde este directorio)."""
import sys
from pathlib import Path

_SERVICE_ROOT = Path(__file__).resolve().parent

_path_str = str(_SERVICE_ROOT)
if _path_str not in sys.path:
    sys.path.insert(0, _path_str)
