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
import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timezone

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("license_check")

# .strip(): un espacio o salto de linea colado al pegar el valor en el .env
# rompia la URL o la firma sin ningun mensaje claro.
LICENSE_SERVER_URL = os.getenv("LICENSE_SERVER_URL", "").strip().rstrip("/")
LICENSE_KEY = os.getenv("LICENSE_KEY", "").strip()
LICENSE_SERVER_PUBLIC_KEY = os.getenv("LICENSE_SERVER_PUBLIC_KEY", "").strip()
# Pasarelas de cobro de la suscripcion (cada 30 dias): PayPal (USD 250) y
# Mercado Pago (pesos, USD 250 al cambio del dia). El cliente elige cual en
# "Pagos y licencia" (o en el login bloqueado). "paypal" es la de siempre.
PROVIDER_LABELS = {"paypal": "PayPal", "mercadopago": "Mercado Pago"}
DEFAULT_PROVIDER = "paypal"


def provider_label(provider: str) -> str:
    return PROVIDER_LABELS.get(provider, provider)


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


async def cancel_subscription() -> None:
    """Le pide al servidor central que cancele el PROXIMO cobro de esta
    LICENSE_KEY, sea cual sea la pasarela con la que se pago (PayPal y/o
    Mercado Pago -- ver licensing-server/app/main.py::cancel_any_subscription):
    es lo que dispara el boton de autoservicio "Cancelar suscripcion". El
    periodo ya pagado sigue corriendo hasta que venza, y no hace falta
    verificar firma: esto no da ningun permiso extra, solo corta un cobro
    futuro."""
    if not is_configured():
        raise LicenseCheckError("LICENSE_SERVER_URL/LICENSE_KEY no configurados")

    url = f"{LICENSE_SERVER_URL}/license/{LICENSE_KEY}/cancel-subscription"
    legacy_url = f"{LICENSE_SERVER_URL}/license/{LICENSE_KEY}/paypal/cancel-subscription"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url)
            if resp.status_code == 404 and _is_route_missing(resp):
                # Servidor central viejo (solo PayPal), anterior al endpoint generico.
                resp = await client.post(legacy_url)
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:300] if exc.response is not None else str(exc)
        raise LicenseCheckError(f"el servidor central rechazo la cancelacion: {detail}") from exc
    except httpx.HTTPError as exc:
        raise LicenseCheckError(f"no se pudo contactar al servidor central de licencias: {exc}") from exc


def _error_detail(resp: httpx.Response) -> str:
    """El motivo que mando el servidor central ({"detail": "..."}) o, si no es
    JSON, el principio del cuerpo -- para mostrarle al usuario algo legible en
    vez de un JSON crudo."""
    try:
        detail = resp.json().get("detail")
        if isinstance(detail, str) and detail:
            return detail[:500]
    except (ValueError, AttributeError):
        pass
    return resp.text[:500]


def _is_route_missing(resp: httpx.Response) -> bool:
    """404 de FastAPI cuando la RUTA no existe ({"detail":"Not Found"}), a
    diferencia de un 404 nuestro ("license_key desconocida", etc.)."""
    try:
        return resp.json().get("detail") == "Not Found"
    except ValueError:
        return False


async def get_payment_link(payer_email: str, provider: str = DEFAULT_PROVIDER) -> str | None:
    """Pide al servidor central el link de aprobacion de la suscripcion
    (PayPal: USD 250 cada 30 dias; Mercado Pago: el equivalente en pesos) para
    ESTA license_key. Devuelve None si el servidor central esta arriba pero esa
    pasarela no esta configurada de su lado (503) -- el caller muestra
    entonces el mensaje de "contacta al operador"."""
    if provider not in PROVIDER_LABELS:
        raise LicenseCheckError(f"pasarela de pago desconocida: {provider}")
    if not is_configured():
        raise LicenseCheckError("LICENSE_SERVER_URL/LICENSE_KEY no configurados")

    url = f"{LICENSE_SERVER_URL}/license/{LICENSE_KEY}/{provider}/subscription-link"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json={"payer_email": payer_email})
            if resp.status_code == 503:
                return None
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPStatusError as exc:
        if exc.response is not None and exc.response.status_code == 409:
            # Ya hay una suscripcion activa: mensaje claro para mostrar tal cual.
            try:
                raise LicenseCheckError(str(exc.response.json().get("detail"))) from exc
            except ValueError:
                pass
        detail = _error_detail(exc.response) if exc.response is not None else str(exc)
        raise LicenseCheckError(f"el servidor central rechazo la generacion del link de pago: {detail}") from exc
    except httpx.HTTPError as exc:
        raise LicenseCheckError(f"no se pudo contactar al servidor central de licencias: {exc}") from exc
    return body.get("approval_url")


async def get_payment_links(payer_email: str) -> dict[str, str]:
    """Un link por cada pasarela disponible ({"paypal": url, "mercadopago": url}),
    para el login bloqueado por falta de pago. Una pasarela que falla o no
    esta configurada simplemente no aparece: el cliente paga con la otra."""
    async def _one(provider: str) -> tuple[str, str | None]:
        try:
            return provider, await get_payment_link(payer_email, provider)
        except LicenseCheckError as exc:
            logger.warning("no se pudo generar el link de %s: %s", provider_label(provider), exc)
            return provider, None

    results = await asyncio.gather(*(_one(p) for p in PROVIDER_LABELS))
    return {provider: url for provider, url in results if url}


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
