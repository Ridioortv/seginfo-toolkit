"""Integracion con PayPal: crear el link de suscripcion que se le manda a
cada cliente (paga a la cuenta de PayPal del operador) y verificar la
firma de los webhooks de PayPal antes de extender ninguna licencia.

Variables de entorno (ver .env.example):
    PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET -- de tu app REST en
        https://developer.paypal.com/dashboard/applications
    PAYPAL_ENV -- "sandbox" (default, para probar) o "live"
    PAYPAL_WEBHOOK_ID -- el id del webhook que registres en el dashboard
        apuntando a https://tu-servidor/webhooks/paypal
    PAYPAL_PLAN_ID -- el id del Billing Plan de $250/30 dias que crees
        en el dashboard (Products & Plans) o via la API de Billing Plans

Sin PAYPAL_CLIENT_ID/SECRET configurados, is_configured() es False y
tanto /admin/clients/{key}/paypal-subscription-link como /webhooks/paypal
devuelven 503 en vez de intentar llamar a una API que no tienen con que
autenticarse."""
import base64
import os
from datetime import datetime, timezone

import httpx

def _env(name: str, default: str = "") -> str:
    """Variable de entorno SIN espacios ni saltos de linea a los costados: al
    pegar un valor en el dashboard de Render es muy facil que se cuele uno
    (un "live " con espacio no es "live" y mandaba las credenciales live al
    entorno sandbox -> HTTP 401 de PayPal)."""
    return os.getenv(name, default).strip()


PAYPAL_CLIENT_ID = _env("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = _env("PAYPAL_CLIENT_SECRET")
PAYPAL_ENV = _env("PAYPAL_ENV", "sandbox").lower() or "sandbox"
PAYPAL_WEBHOOK_ID = _env("PAYPAL_WEBHOOK_ID")
PAYPAL_PLAN_ID = _env("PAYPAL_PLAN_ID")
PAYPAL_RETURN_URL = _env("PAYPAL_RETURN_URL", "https://www.google.com/?sentinelops_subscribed=1") or "https://www.google.com/?sentinelops_subscribed=1"
PAYPAL_CANCEL_URL = _env("PAYPAL_CANCEL_URL", "https://www.google.com/?sentinelops_cancelled=1") or "https://www.google.com/?sentinelops_cancelled=1"

# Eventos de PayPal que representan un pago efectivamente recibido --
# unicos que disparan una extension de la licencia. Todo lo demas
# (CANCELLED, SUSPENDED, EXPIRED, PAYMENT.SALE.DENIED, etc) se ignora a
# proposito: si el cliente cancela, se deja que el periodo YA PAGADO
# corra hasta el final (is_org_active() del lado del cliente corta solo
# cuando subscription_expires_at pasa) en vez de cortarle el acceso que
# ya pago.
#
# IMPORTANTE: SOLO PAYMENT.SALE.COMPLETED extiende la licencia. PayPal manda
# BILLING.SUBSCRIPTION.ACTIVATED al aprobar el cliente Y, aparte,
# PAYMENT.SALE.COMPLETED por el primer cobro -- si los dos extendieran,
# el primer pago daria 60 dias en vez de 30. ACTIVATED solo sirve para
# vincular el subscription_id con la license_key (ver LINK_EVENTS).
PAYMENT_RECEIVED_EVENTS = {
    "PAYMENT.SALE.COMPLETED",  # cada cobro (el primero incluido)
}
LINK_EVENTS = {
    "BILLING.SUBSCRIPTION.ACTIVATED",  # aprobacion: vincula subscription_id <-> license_key
}


class PayPalError(Exception):
    pass


def is_configured() -> bool:
    return bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET)


def _base_url() -> str:
    return "https://api-m.paypal.com" if PAYPAL_ENV in ("live", "production", "prod") else "https://api-m.sandbox.paypal.com"


async def _get_access_token(client: httpx.AsyncClient) -> str:
    basic = base64.b64encode(f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode()).decode()
    resp = await client.post(
        f"{_base_url()}/v1/oauth2/token",
        headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "client_credentials"},
    )
    if resp.status_code in (401, 403):
        # Antes esto era un raise_for_status() sin atrapar: el cliente veia un
        # "Internal Server Error" sin pista de la causa (casi siempre, credenciales
        # de sandbox con PAYPAL_ENV=live o al reves, o un secret mal pegado).
        raise PayPalError(
            f"PayPal rechazo las credenciales (HTTP {resp.status_code}). Revisa PAYPAL_CLIENT_ID y "
            f"PAYPAL_CLIENT_SECRET en el servidor y que PAYPAL_ENV (hoy: {PAYPAL_ENV}) coincida con el "
            "tipo de credenciales (sandbox o live)."
        )
    if resp.status_code >= 400:
        raise PayPalError(f"PayPal no entrego el token de acceso: HTTP {resp.status_code}")
    return resp.json()["access_token"]


async def create_subscription_approval_link(
    license_key: str, plan_id: str | None = None, payer_email: str | None = None
) -> tuple[str, str]:
    """Crea una suscripcion en PayPal (todavia sin aprobar por el
    cliente) con custom_id=license_key, y devuelve (subscription_id,
    approval_url). El operador manda approval_url al cliente; cuando lo
    aprueba, PayPal factura a la cuenta del operador y dispara
    BILLING.SUBSCRIPTION.ACTIVATED."""
    if not is_configured():
        raise PayPalError("PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET no configurados")
    plan_id = plan_id or PAYPAL_PLAN_ID
    if not plan_id:
        raise PayPalError("No hay plan_id (PAYPAL_PLAN_ID vacio y no se paso uno explicito)")

    async with httpx.AsyncClient(timeout=15) as client:
        token = await _get_access_token(client)
        payload = {
            "plan_id": plan_id,
            "custom_id": license_key,
            "application_context": {
                "brand_name": "TERO Security",
                "user_action": "SUBSCRIBE_NOW",
                "return_url": PAYPAL_RETURN_URL,
                "cancel_url": PAYPAL_CANCEL_URL,
            },
        }
        if payer_email:
            payload["subscriber"] = {"email_address": payer_email}
        resp = await client.post(
            f"{_base_url()}/v1/billing/subscriptions",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )
        if resp.status_code >= 400:
            raise PayPalError(f"PayPal rechazo la creacion de la suscripcion: {resp.status_code} {resp.text[:500]}")
        body = resp.json()

    subscription_id = body["id"]
    approve_link = next((l["href"] for l in body.get("links", []) if l.get("rel") == "approve"), None)
    if not approve_link:
        raise PayPalError("la respuesta de PayPal no incluyo un link 'approve'")
    return subscription_id, approve_link


async def get_subscription_status(subscription_id: str) -> str | None:
    """Estado de una suscripcion en PayPal (APPROVAL_PENDING, APPROVED, ACTIVE,
    SUSPENDED, CANCELLED, EXPIRED). None si PayPal no la conoce (404). Se usa
    para no crear una SEGUNDA suscripcion cuando ya hay una cobrando."""
    if not is_configured():
        raise PayPalError("PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET no configurados")
    async with httpx.AsyncClient(timeout=15) as client:
        token = await _get_access_token(client)
        resp = await client.get(
            f"{_base_url()}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise PayPalError(f"no se pudo consultar la suscripcion: {resp.status_code} {resp.text[:300]}")
        return str(resp.json().get("status", "")).upper() or None


async def cancel_subscription(subscription_id: str, reason: str = "Cancelada por el cliente") -> None:
    """Cancela el PROXIMO cobro de la suscripcion en PayPal. El periodo ya
    pagado sigue corriendo (no se toca la fecha de vencimiento)."""
    if not is_configured():
        raise PayPalError("PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET no configurados")
    async with httpx.AsyncClient(timeout=15) as client:
        token = await _get_access_token(client)
        resp = await client.post(
            f"{_base_url()}/v1/billing/subscriptions/{subscription_id}/cancel",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"reason": reason[:128]},
        )
        # 204 = cancelada. 422 = ya estaba cancelada/expirada: para el cliente
        # el resultado es el mismo (no se le cobra mas), no es un error.
        if resp.status_code not in (200, 204, 422):
            raise PayPalError(f"PayPal rechazo la cancelacion: {resp.status_code} {resp.text[:500]}")


async def verify_webhook_signature(headers: dict, event_body: dict) -> bool:
    """Confirma que un webhook realmente vino de PayPal (y no de
    cualquiera que le pegue a /webhooks/paypal con un event_type
    inventado) usando el endpoint oficial de verificacion de PayPal --
    mas simple y menos propenso a errores que validar el certificado a
    mano en este lado."""
    if not is_configured() or not PAYPAL_WEBHOOK_ID:
        return False

    required = ("paypal-auth-algo", "paypal-cert-url", "paypal-transmission-id",
                "paypal-transmission-sig", "paypal-transmission-time")
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if not all(h in lower_headers for h in required):
        return False

    async with httpx.AsyncClient(timeout=15) as client:
        token = await _get_access_token(client)
        resp = await client.post(
            f"{_base_url()}/v1/notifications/verify-webhook-signature",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "auth_algo": lower_headers["paypal-auth-algo"],
                "cert_url": lower_headers["paypal-cert-url"],
                "transmission_id": lower_headers["paypal-transmission-id"],
                "transmission_sig": lower_headers["paypal-transmission-sig"],
                "transmission_time": lower_headers["paypal-transmission-time"],
                "webhook_id": PAYPAL_WEBHOOK_ID,
                "webhook_event": event_body,
            },
        )
        if resp.status_code >= 400:
            return False
        return resp.json().get("verification_status") == "SUCCESS"


def resolve_license_key_lookup(event: dict) -> tuple[str, str]:
    """De un evento de PayPal ya verificado, devuelve (metodo, valor)
    para encontrar el cliente: los eventos BILLING.SUBSCRIPTION.* traen
    el id de la suscripcion en resource.id; los de pago recurrente
    (PAYMENT.SALE.*) lo traen en resource.billing_agreement_id. custom_id
    (si esta presente) es el fallback mas directo -- es literalmente la
    license_key, seteada al crear la suscripcion."""
    resource = event.get("resource", {}) or {}
    custom_id = resource.get("custom_id")
    if custom_id:
        return "license_key", custom_id
    event_type = event.get("event_type", "")
    if event_type.startswith("BILLING.SUBSCRIPTION"):
        return "paypal_subscription_id", resource.get("id", "")
    return "paypal_subscription_id", resource.get("billing_agreement_id", "")
