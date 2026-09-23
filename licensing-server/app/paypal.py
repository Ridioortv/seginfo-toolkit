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

PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
PAYPAL_ENV = os.getenv("PAYPAL_ENV", "sandbox")
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")
PAYPAL_PLAN_ID = os.getenv("PAYPAL_PLAN_ID", "")
PAYPAL_RETURN_URL = os.getenv("PAYPAL_RETURN_URL", "https://www.google.com/?sentinelops_subscribed=1")
PAYPAL_CANCEL_URL = os.getenv("PAYPAL_CANCEL_URL", "https://www.google.com/?sentinelops_cancelled=1")

# Eventos de PayPal que representan un pago efectivamente recibido --
# unicos que disparan una extension de la licencia. Todo lo demas
# (CANCELLED, SUSPENDED, EXPIRED, PAYMENT.SALE.DENIED, etc) se ignora a
# proposito: si el cliente cancela, se deja que el periodo YA PAGADO
# corra hasta el final (is_org_active() del lado del cliente corta solo
# cuando subscription_expires_at pasa) en vez de cortarle el acceso que
# ya pago.
PAYMENT_RECEIVED_EVENTS = {
    "BILLING.SUBSCRIPTION.ACTIVATED",  # primer pago, al aprobar la suscripcion
    "PAYMENT.SALE.COMPLETED",  # cada cobro recurrente posterior
}


class PayPalError(Exception):
    pass


def is_configured() -> bool:
    return bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET)


def _base_url() -> str:
    return "https://api-m.sandbox.paypal.com" if PAYPAL_ENV != "live" else "https://api-m.paypal.com"


async def _get_access_token(client: httpx.AsyncClient) -> str:
    basic = base64.b64encode(f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode()).decode()
    resp = await client.post(
        f"{_base_url()}/v1/oauth2/token",
        headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "client_credentials"},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def create_subscription_approval_link(license_key: str, plan_id: str | None = None) -> tuple[str, str]:
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
        resp = await client.post(
            f"{_base_url()}/v1/billing/subscriptions",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "plan_id": plan_id,
                "custom_id": license_key,
                "application_context": {
                    "brand_name": "SentinelOps",
                    "user_action": "SUBSCRIBE_NOW",
                    "return_url": PAYPAL_RETURN_URL,
                    "cancel_url": PAYPAL_CANCEL_URL,
                },
            },
        )
        if resp.status_code >= 400:
            raise PayPalError(f"PayPal rechazo la creacion de la suscripcion: {resp.status_code} {resp.text[:500]}")
        body = resp.json()

    subscription_id = body["id"]
    approve_link = next((l["href"] for l in body.get("links", []) if l.get("rel") == "approve"), None)
    if not approve_link:
        raise PayPalError("la respuesta de PayPal no incluyo un link 'approve'")
    return subscription_id, approve_link


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
