"""Cliente del servidor central de licencias (arquitectura elegida por el
operador: cada cliente corre su propia copia on-prem desde el .rar, y un
servidor central que aloja el operador es la fuente de verdad de "esta
organizacion tiene la suscripcion al dia").

Por que hace falta esto y no alcanza con la columna
Organization.subscription_expires_at sola: esa columna vive en el
Postgres del CLIENTE, en su propia maquina -- cualquier cliente con
acceso a su propia base (todo cliente on-prem, por definicion) podria
editarla a mano para "renovarse" gratis. Este modulo la trata como un
CACHE local que este servicio (auth-service) refresca periodicamente
contra el servidor central, cuya respuesta viene firmada con una clave
privada que SOLO el servidor central tiene -- el cliente puede leer/
editar su propia base todo lo que quiera, pero no puede fabricar una
respuesta firmada sin esa clave.

Si LICENSE_SERVER_URL no esta configurado, este modulo no hace nada
(instalaciones que todavia gestionan la suscripcion solo a mano via
PUT /auth/organizations/{id}/subscription -- ver app/services.py).

Formato de la respuesta firmada (ver licensing-server/app/main.py):
    {"license_key": str, "valid": bool, "valid_until": iso8601|null, "checked_at": iso8601}
firmada con Ed25519 sobre json.dumps(payload, sort_keys=True,
separators=(",", ":")).encode(), en base64 en el header X-Signature."""
import base64
import json
import logging
import os
from datetime import datetime, timezone

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("license_check")

LICENSE_SERVER_URL = os.getenv("LICENSE_SERVER_URL", "").rstrip("/")
LICENSE_KEY = os.getenv("LICENSE_KEY", "")
LICENSE_SERVER_PUBLIC_KEY = os.getenv("LICENSE_SERVER_PUBLIC_KEY", "")


class LicenseCheckError(Exception):
    """Fallo de red, HTTP, o de firma -- el caller decide que hacer (ver
    is_configured()/check_license() en services.py de auth-service, que
    trata esto como 'no se pudo confirmar esta vez' y cae al cache local
    con su ventana de gracia, no como 'la licencia es invalida')."""


def is_configured() -> bool:
    return bool(LICENSE_SERVER_URL and LICENSE_KEY)


def _public_key() -> Ed25519PublicKey:
    raw = base64.b64decode(LICENSE_SERVER_PUBLIC_KEY)
    return Ed25519PublicKey.from_public_bytes(raw)


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


async def check_license() -> tuple[bool, datetime | None]:
    """Consulta al servidor central el estado de LICENSE_KEY y verifica su
    firma. Devuelve (valid, valid_until) si la respuesta es autentica.
    Tira LicenseCheckError en cualquier otro caso (red, HTTP, firma
    invalida, formato inesperado) -- nunca devuelve un resultado sin
    verificar la firma primero."""
    if not is_configured():
        raise LicenseCheckError("LICENSE_SERVER_URL/LICENSE_KEY no configurados")

    url = f"{LICENSE_SERVER_URL}/license/{LICENSE_KEY}/status"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            body = resp.json()
            signature_b64 = resp.headers.get("X-Signature", "")
    except httpx.HTTPError as exc:
        raise LicenseCheckError(f"no se pudo contactar al servidor central de licencias: {exc}") from exc

    if not signature_b64:
        raise LicenseCheckError("la respuesta del servidor central no viene firmada (falta X-Signature)")

    try:
        signature = base64.b64decode(signature_b64)
        _public_key().verify(signature, _canonical_bytes(body))
    except (InvalidSignature, ValueError) as exc:
        # Esto es lo que importa de verdad: si alguien (un proxy MITM en la
        # red del cliente, o el cliente mismo apuntando LICENSE_SERVER_URL a
        # un servidor propio) intenta devolver "valid: true" sin la clave
        # privada correcta, la verificacion falla aca y NUNCA se confia en
        # el body.
        raise LicenseCheckError(f"firma invalida en la respuesta del servidor central: {exc}") from exc

    if body.get("license_key") != LICENSE_KEY:
        raise LicenseCheckError("la respuesta firmada corresponde a otra license_key (¿replay?)")

    valid = bool(body.get("valid"))
    valid_until_raw = body.get("valid_until")
    valid_until = datetime.fromisoformat(valid_until_raw) if valid_until_raw else None
    return valid, valid_until
