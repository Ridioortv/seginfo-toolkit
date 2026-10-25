"""Pytest bootstrap: hace que `import app...` y `import backend.shared...`
funcionen igual que dentro del contenedor Docker de este servicio (donde
Dockerfile copia ./app y ./backend/shared bajo /app y setea
PYTHONPATH=/app), sin necesitar Docker ni variables de entorno especiales
para correr los tests localmente o en CI (`pytest` desde la raiz del repo
o desde este directorio)."""
import os
import sys
from pathlib import Path

_SERVICE_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _SERVICE_ROOT.parent.parent.parent

for _path in (_SERVICE_ROOT, _REPO_ROOT):
    _path_str = str(_path)
    if _path_str not in sys.path:
        sys.path.insert(0, _path_str)

# La cadena de custodia manda eventos por red a case-service: los tests no lo necesitan.
os.environ.setdefault("TERO_CUSTODY_DISABLED", "1")
