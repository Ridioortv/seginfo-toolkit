"""Token interno para POST /logs/ingest de siem-service.

Ese endpoint no lleva JWT de usuario (lo usan otros microservicios y, en
despliegues reales, forwarders externos). Dos tipos de credencial:

- SIEM_INGEST_TOKEN (maestro): lo usan solo los servicios internos del stack
  (scan/asm/cloud). Puede escribir en cualquier organizacion.
- Token por organizacion = HMAC-SHA256(SIEM_INGEST_TOKEN, "siem-ingest:<org_id>"):
  es el que se le da a un forwarder externo de UN tenant (lo obtiene el admin
  de la organizacion en GET /logs/ingest-token de siem-service). Solo vale
  para esa organizacion: no puede inyectar eventos/alertas ni disparar SOAR en
  otra (antes todos los forwarders compartian el maestro).

Si SIEM_INGEST_TOKEN no esta definido, el endpoint solo queda abierto con
ENVIRONMENT=development; en cualquier otro entorno falla cerrado. Tampoco se
acepta el valor de ejemplo del .env.example fuera de desarrollo."""
import hashlib
import hmac
import os

HEADER_NAME = "X-Ingest-Token"
_PLACEHOLDER = "changeme-ingest-token"


def _is_development() -> bool:
    return os.getenv("ENVIRONMENT", "development") == "development"


def ingest_headers() -> dict[str, str]:
    """Headers que deben mandar los servicios internos al llamar a /logs/ingest."""
    token = os.getenv("SIEM_INGEST_TOKEN")
    return {HEADER_NAME: token} if token else {}


def org_ingest_token(organization_id: str) -> str | None:
    """Token de ingesta derivado para UNA organizacion (None si no hay maestro)."""
    master = os.getenv("SIEM_INGEST_TOKEN")
    if not master:
        return None
    return hmac.new(master.encode(), f"siem-ingest:{organization_id}".encode(), hashlib.sha256).hexdigest()


def ingest_token_valid(provided: str | None, organization_id: str | None = None) -> bool:
    """organization_id: organizacion a la que se quiere escribir. Con el token
    maestro alcanza; con un token derivado tiene que coincidir con esa org."""
    expected = os.getenv("SIEM_INGEST_TOKEN")
    if not expected:
        return _is_development()
    if expected == _PLACEHOLDER and not _is_development():
        return False
    if not provided:
        return False
    if hmac.compare_digest(provided.encode(), expected.encode()):
        return True
    if organization_id:
        derived = org_ingest_token(organization_id)
        return derived is not None and hmac.compare_digest(provided.encode(), derived.encode())
    return False
