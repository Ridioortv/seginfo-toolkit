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
import asyncio
import base64
import hashlib
import logging
import os
from datetime import datetime, timezone

import httpx

from app import db

logger = logging.getLogger("paypal")

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
PAYPAL_PREFILL_EMAIL = _env("PAYPAL_PREFILL_EMAIL").lower() in ("1", "true", "yes")
PAYPAL_CANCEL_URL = _env("PAYPAL_CANCEL_URL", "https://www.google.com/?sentinelops_cancelled=1") or "https://www.google.com/?sentinelops_cancelled=1"
# Si el PAYPAL_PLAN_ID no existe en PayPal (404 INVALID_RESOURCE_ID: casi siempre
# es un plan de sandbox usado con credenciales live o al reves, o un plan de
# otra cuenta), el servidor puede crear solo el plan de USD 250 cada 30 dias,
# guardarlo en la base y reutilizarlo. Por defecto SOLO en sandbox; en live hay
# que pedirlo con PAYPAL_AUTO_CREATE_PLAN=1 (0 lo apaga tambien en sandbox).
PAYPAL_AUTO_CREATE_PLAN = _env("PAYPAL_AUTO_CREATE_PLAN").lower()
PAYPAL_PRICE_USD = _env("PAYPAL_PRICE_USD", "250") or "250"
try:
    PAYPAL_PERIOD_DAYS = int(_env("PAYPAL_PERIOD_DAYS", "30") or "30")
except ValueError:
    PAYPAL_PERIOD_DAYS = 30
_known_missing_plans: set[str] = set()
_plan_lock: tuple | None = None

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
    return "https://api-m.paypal.com" if _is_live() else "https://api-m.sandbox.paypal.com"


def _is_live() -> bool:
    return PAYPAL_ENV in ("live", "production", "prod")


def auto_create_plan_allowed() -> bool:
    if PAYPAL_AUTO_CREATE_PLAN in ("0", "false", "no"):
        return False
    if PAYPAL_AUTO_CREATE_PLAN in ("1", "true", "yes"):
        return True
    return not _is_live()


def _plan_setting_name() -> str:
    # Un plan solo existe en SU entorno y SU cuenta: la clave incluye ambos.
    who = hashlib.sha256(PAYPAL_CLIENT_ID.encode()).hexdigest()[:12]
    return f"paypal_plan:{'live' if _is_live() else 'sandbox'}:{who}"


def _stored_plan() -> str | None:
    try:
        return db.get_setting(_plan_setting_name())
    except Exception:  # la base no puede impedir cobrar: sin plan guardado se crea otro
        logger.warning("no se pudo leer el plan de PayPal guardado", exc_info=True)
        return None


def _get_plan_lock() -> asyncio.Lock:
    """Un lock por event loop: dos links simultaneos no deben crear dos planes."""
    global _plan_lock
    loop = asyncio.get_running_loop()
    if _plan_lock is None or _plan_lock[0] is not loop:
        _plan_lock = (loop, asyncio.Lock())
    return _plan_lock[1]


def _is_missing_plan(resp: httpx.Response) -> bool:
    """404 INVALID_RESOURCE_ID al crear la suscripcion = el plan_id no existe."""
    if resp.status_code != 404:
        return False
    try:
        details = resp.json().get("details") or []
    except (ValueError, AttributeError):
        return False
    return any(isinstance(d, dict) and d.get("issue") == "INVALID_RESOURCE_ID" for d in details)


def _missing_plan_error(plan_id: str, explicit: bool) -> str:
    which = "el plan indicado" if explicit else "el plan configurado"
    return (
        f"PayPal no encontro {which} ({plan_id}) en el entorno {PAYPAL_ENV}. Los planes de sandbox y de live "
        "son distintos y cada plan pertenece a la cuenta de PayPal que lo creo: tiene que ser un plan creado en "
        f"{PAYPAL_ENV} con las mismas credenciales (PAYPAL_CLIENT_ID) que usa este servidor. Solucion: corre "
        f"`python create_paypal_plan.py` con PAYPAL_ENV={PAYPAL_ENV} y pega el PAYPAL_PLAN_ID que imprime en "
        "las variables del servidor, o define PAYPAL_AUTO_CREATE_PLAN=1 para que el servidor cree el plan solo."
    )


async def create_plan(client: httpx.AsyncClient, token: str, price: str, days: int) -> str:
    """Crea el producto y el plan (price USD cada `days` dias, renovacion
    automatica) y devuelve el plan_id. Lo usan create_paypal_plan.py y la
    creacion automatica."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = _base_url()
    r = await client.post(
        f"{base}/v1/catalogs/products", headers=headers,
        json={"name": "TERO Security", "type": "SERVICE", "category": "SOFTWARE"},
    )
    if r.status_code >= 400:
        raise PayPalError(f"PayPal no dejo crear el plan (fallo el producto): {r.status_code} {r.text[:300]}")
    product_id = r.json()["id"]
    r = await client.post(
        f"{base}/v1/billing/plans", headers=headers,
        json={
            "product_id": product_id,
            "name": f"TERO Security USD {price} cada {days} dias",
            "billing_cycles": [{
                "frequency": {"interval_unit": "DAY", "interval_count": days},
                "tenure_type": "REGULAR",
                "sequence": 1,
                "total_cycles": 0,
                "pricing_scheme": {"fixed_price": {"value": price, "currency_code": "USD"}},
            }],
            "payment_preferences": {"auto_bill_outstanding": True, "payment_failure_threshold": 3},
        },
    )
    if r.status_code >= 400:
        raise PayPalError(f"PayPal no dejo crear el plan: {r.status_code} {r.text[:300]}")
    return r.json()["id"]


async def _provision_plan(client: httpx.AsyncClient, token: str, stale: str | None) -> str:
    """Plan guardado en la base si sirve; si no (o si es el que acaba de fallar),
    crea uno nuevo y lo guarda."""
    async with _get_plan_lock():
        stored = _stored_plan()
        if stored and stored != stale and stored not in _known_missing_plans:
            return stored
        plan_id = await create_plan(client, token, PAYPAL_PRICE_USD, PAYPAL_PERIOD_DAYS)
        try:
            db.set_setting(_plan_setting_name(), plan_id)
        except Exception:
            logger.warning("no se pudo guardar el plan de PayPal creado (%s)", plan_id, exc_info=True)
        logger.warning("PayPal: el plan configurado no existia; se creo el plan %s (USD %s / %s dias, %s)",
                       plan_id, PAYPAL_PRICE_USD, PAYPAL_PERIOD_DAYS, PAYPAL_ENV)
        return plan_id


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
    explicit = bool(plan_id)
    plan_id = plan_id or PAYPAL_PLAN_ID
    if not explicit and plan_id in _known_missing_plans:
        plan_id = _stored_plan() or ""
    if not plan_id and not auto_create_plan_allowed():
        raise PayPalError("No hay plan_id (PAYPAL_PLAN_ID vacio y no se paso uno explicito)")

    async with httpx.AsyncClient(timeout=15) as client:
        token = await _get_access_token(client)
        if not plan_id:
            plan_id = await _provision_plan(client, token, None)
        for attempt in range(3):
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
            # Por defecto NO se precarga el email del suscriptor: el email de login del
            # cliente casi nunca es el de su cuenta PayPal, y si coincide con el de la
            # cuenta que cobra PayPal rechaza el checkout con una pantalla de error generica.
            if payer_email and PAYPAL_PREFILL_EMAIL:
                payload["subscriber"] = {"email_address": payer_email}
            resp = await client.post(
                f"{_base_url()}/v1/billing/subscriptions",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
            )
            if not _is_missing_plan(resp):
                break
            # El plan no existe en este entorno/cuenta. Un plan pedido a mano por el
            # operador nunca se reemplaza; el configurado, solo si esta permitido.
            if explicit or not auto_create_plan_allowed() or attempt == 2:
                raise PayPalError(_missing_plan_error(plan_id, explicit))
            _known_missing_plans.add(plan_id)
            plan_id = await _provision_plan(client, token, plan_id)
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
