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


async def cancel_mercadopago_subscription() -> None:
    """Le pide al servidor central que cancele el PROXIMO cobro
    automatico de Mercado Pago vinculado a esta LICENSE_KEY (ver
    licensing-server/app/main.py::mercadopago_cancel_subscription) --
    lo que dispara el boton de autoservicio "Cancelar suscripcion" en
    la organizacion (ver auth-service/app/main.py). No cambia
    subscription_expires_at ni acá ni del lado del servidor central: el
    periodo ya pagado sigue corriendo hasta que venza, is_org_active()
    no se entera de esto hasta esa fecha. No hace falta verificar
    ninguna firma acá (a diferencia de check_license): esto no le da
    ningun permiso extra al cliente, solo corta un cobro futuro."""
    if not is_configured():
        raise LicenseCheckError("LICENSE_SERVER_URL/LICENSE_KEY no configurados")

    url = f"{LICENSE_SERVER_URL}/license/{LICENSE_KEY}/mercadopago/cancel-subscription"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url)
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:300] if exc.response is not None else str(exc)
        raise LicenseCheckError(f"el servidor central rechazo la cancelacion: {detail}") from exc
    except httpx.HTTPError as exc:
        raise LicenseCheckError(f"no se pudo contactar al servidor central de licencias: {exc}") from exc


async def get_mercadopago_payment_link(payer_email: str) -> str | None:
    """Le pide al servidor central un link de pago (Mercado Pago) para
    ESTA license_key -- autoservicio para cuando la suscripcion esta
    vencida (ver _reject_if_org_inactive en auth-service/app/main.py),
    asi quien intenta entrar puede pagar y recuperar el acceso sin
    escribirle al operador. Devuelve None (no LicenseCheckError) si el
    servidor central esta arriba pero Mercado Pago no esta configurado
    del lado suyo (503) -- eso no es un fallo de red/firma, es "esta
    instalacion no ofrece pago automatico", y el caller ya sabe mostrar
    el mensaje generico de "contacta al operador" en ese caso."""
    if not is_configured():
        raise LicenseCheckError("LICENSE_SERVER_URL/LICENSE_KEY no configurados")

    url = f"{LICENSE_SERVER_URL}/license/{LICENSE_KEY}/mercadopago/subscription-link"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={"payer_email": payer_email})
            if resp.status_code == 503:
                return None
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:300] if exc.response is not None else str(exc)
        raise LicenseCheckError(f"el servidor central rechazo la generacion del link de pago: {detail}") from exc
    except httpx.HTTPError as exc:
        raise LicenseCheckError(f"no se pudo contactar al servidor central de licencias: {exc}") from exc
    return body.get("init_point")


async def get_subscription_history() -> list[str]:
    """Trae el historial de eventos (pagos, cancelaciones, renovaciones)
    de ESTA license_key desde el servidor central -- lo que alimenta la
    seccion "Pagos y licencia" del frontend (ver
    GET /auth/organizations/{id}/subscription/history en
    auth-service/app/main.py). Devuelve las lineas mas nuevas primero."""
    if not is_configured():
        raise LicenseCheckError("LICENSE_SERVER_URL/LICENSE_KEY no configurados")

    url = f"{LICENSE_SERVER_URL}/license/{LICENSE_KEY}/history"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPError as exc:
        raise LicenseCheckError(f"no se pudo contactar al servidor central de licencias: {exc}") from exc

    notes = body.get("notes") or ""
    lines = [ln for ln in notes.split("\n") if ln]
    return list(reversed(lines))
