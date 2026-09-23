"""Origenes CORS permitidos, compartido por los 11 microservicios.

Antes cada `main.py` tenia `allow_origins=["*"]` hardcodeado -- eso deja
que CUALQUIER pagina web (no solo el frontend de SentinelOps) le pida al
navegador de un usuario logueado que haga requests autenticados contra
la API, si a esa pagina se le ocurre. Con JWT en el header Authorization
(no en una cookie) el riesgo practico es acotado -- un sitio de terceros
no puede leer el token del localStorage del usuario -- pero igual no hay
ninguna razon para aceptar cualquier origen, y varios lint/scanners de
seguridad lo marcan como hallazgo por defecto.

CORS_ALLOWED_ORIGINS (env var) es una lista separada por comas de
origenes exactos (ej. "http://localhost:5173,https://sentinelops.tuempresa.com").
Si no esta seteada, se cae a FRONTEND_URL (que ya existe para el redirect
de SSO) o a http://localhost:5173 como ultimo recurso -- nunca a "*"."""
import os


def get_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOWED_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if origins:
        return origins
    fallback = os.getenv("FRONTEND_URL", "http://localhost:5173")
    return [fallback]
