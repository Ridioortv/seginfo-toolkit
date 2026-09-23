"""Servidor central de licencias de SentinelOps.

Este servicio NO se distribuye a los clientes (no va dentro del .rar) --
lo aloja el operador (ver licensing-server/README.md para donde y como
desplegarlo) y es la fuente de verdad de que organizacion tiene la
suscripcion al dia. Cada instalacion on-prem de un cliente (su
auth-service) lo consulta periodicamente via backend/shared/license_check.py
y cachea localmente la respuesta -- ver el razonamiento completo en ese
modulo y en Organization.subscription_expires_at (backend/services/auth-service/app/models.py).

Autenticacion: los endpoints /admin/* (crear/extender/revocar un
cliente, o generar un link de suscripcion de PayPal/Mercado Pago)
requieren `Authorization: Bearer <ADMIN_TOKEN>` -- son para uso
exclusivo del operador. Los webhooks de pago (/webhooks/paypal,
/webhooks/mercadopago) son la excepcion: no llevan ese token (ninguna
de las dos pasarelas lo manda), se autentican solo con su propia firma
y llaman internamente a la misma logica que usa /admin/.../extend. El
endpoint
/license/{license_key}/status es publico a proposito: cualquier
instalacion on-prem necesita poder consultarlo sin credenciales previas
mas que su propia license_key, y la respuesta viene firmada (nunca
autenticada por sesion) para que ningun intermediario pueda alterarla
sin que el cliente lo detecte."""
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app import db, mercadopago, paypal
from app.signing import sign_payload

logger = logging.getLogger("licensing-server")

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DEFAULT_PERIOD_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ADMIN_TOKEN:
        raise RuntimeError(
            "ADMIN_TOKEN no esta configurado -- sin esto, los endpoints /admin/* "
            "(crear/extender licencias) quedarian abiertos a cualquiera. Setealo "
            "antes de arrancar (ver licensing-server/README.md)."
        )
    db.init_db()
    yield


app = FastAPI(title="SentinelOps Licensing Server", version="0.1.0", lifespan=lifespan)


def require_admin(authorization: str = Header(default="")) -> None:
    token = authorization.removeprefix("Bearer ").strip()
    # compare_digest (no ==) para no filtrar el largo del token via timing.
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Token de administrador invalido")


@app.get("/health")
def health():
    return {"status": "ok", "service": "licensing-server"}


class ClientCreate(BaseModel):
    org_name: str = Field(..., min_length=1)
    license_key: str | None = Field(default=None, description="Si se omite, se genera uno random")
    days: int = Field(default=DEFAULT_PERIOD_DAYS, ge=1)
    notes: str = ""


class ClientOut(BaseModel):
    license_key: str
    org_name: str
    subscription_expires_at: str
    notes: str
    created_at: str


class ExtendRequest(BaseModel):
    days: int = Field(default=DEFAULT_PERIOD_DAYS, ge=1)


class PaypalLinkRequest(BaseModel):
    plan_id: str | None = Field(default=None, description="Si se omite, usa PAYPAL_PLAN_ID")


class PaypalLinkOut(BaseModel):
    subscription_id: str
    approval_url: str


class MercadoPagoLinkRequest(BaseModel):
    payer_email: str = Field(..., min_length=3, description="Email del cliente en Mercado Pago -- lo pide MP para vincular la suscripcion")
    plan_id: str | None = Field(default=None, description="Si se omite, usa MERCADOPAGO_PLAN_ID")


class MercadoPagoLinkOut(BaseModel):
    preapproval_id: str
    init_point: str


def _extend_expiry(license_key: str, days: int) -> None:
    """Logica compartida por el endpoint admin y el webhook de PayPal --
    se extiende desde la fecha de vencimiento ACTUAL (nunca desde
    'ahora'), asi que renovar unos dias antes de que venza (o que el
    cobro recurrente de PayPal llegue un poco antes) no le hace perder
    al cliente los dias que le quedaban. Si ya esta vencida, arranca de
    nuevo desde ahora."""
    row = db.get_client(license_key)
    if row is None:
        raise LookupError(license_key)
    current_expiry = datetime.fromisoformat(row["subscription_expires_at"])
    base = max(current_expiry, _now())
    new_expiry = (base + timedelta(days=days)).isoformat()
    db.set_expiry(license_key, new_expiry)


@app.post("/admin/clients", response_model=ClientOut, status_code=status.HTTP_201_CREATED)
def create_client(payload: ClientCreate, _: None = Depends(require_admin)):
    license_key = payload.license_key or secrets.token_urlsafe(24)
    if db.get_client(license_key) is not None:
        raise HTTPException(status_code=400, detail="Esa license_key ya existe")
    expires_at = (_now() + timedelta(days=payload.days)).isoformat()
    db.create_client(license_key, payload.org_name, expires_at, payload.notes)
    row = db.get_client(license_key)
    return ClientOut(**dict(row))


@app.get("/admin/clients", response_model=list[ClientOut])
def list_clients(_: None = Depends(require_admin)):
    return [ClientOut(**dict(row)) for row in db.list_clients()]


@app.post("/admin/clients/{license_key}/extend", response_model=ClientOut)
def extend_client(license_key: str, payload: ExtendRequest, _: None = Depends(require_admin)):
    try:
        _extend_expiry(license_key, payload.days)
    except LookupError:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    return ClientOut(**dict(db.get_client(license_key)))


@app.post("/admin/clients/{license_key}/paypal-subscription-link", response_model=PaypalLinkOut)
async def paypal_subscription_link(license_key: str, payload: PaypalLinkRequest, _: None = Depends(require_admin)):
    """Genera el link de PayPal que le mandas al cliente para que apruebe
    la suscripcion de $250/30 dias A TU cuenta de PayPal. Cuando lo
    aprueba, PayPal factura y dispara BILLING.SUBSCRIPTION.ACTIVATED
    contra /webhooks/paypal, que extiende la licencia solo."""
    if db.get_client(license_key) is None:
        raise HTTPException(status_code=404, detail="license_key desconocida -- creala primero con POST /admin/clients")
    if not paypal.is_configured():
        raise HTTPException(status_code=503, detail="PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET no configurados en este servidor")
    try:
        subscription_id, approval_url = await paypal.create_subscription_approval_link(license_key, payload.plan_id)
    except paypal.PayPalError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.set_paypal_subscription_id(license_key, subscription_id)
    return PaypalLinkOut(subscription_id=subscription_id, approval_url=approval_url)


@app.post("/webhooks/paypal", status_code=status.HTTP_204_NO_CONTENT)
async def paypal_webhook(request: Request):
    """PayPal le pega aca en cada evento de las suscripciones (pago
    recibido, cancelacion, etc -- ver app/paypal.py::PAYMENT_RECEIVED_EVENTS
    para cuales efectivamente extienden una licencia). Publico por
    definicion (PayPal no manda tu ADMIN_TOKEN), asi que la unica
    proteccion real es la verificacion de firma -- sin ella, cualquiera
    podria pegarle a esta URL con un event_type inventado y renovarse
    gratis."""
    if not paypal.is_configured():
        raise HTTPException(status_code=503, detail="PayPal no esta configurado en este servidor")

    event = await request.json()
    verified = await paypal.verify_webhook_signature(dict(request.headers), event)
    if not verified:
        logger.warning("webhook de PayPal con firma invalida o no verificable -- ignorado")
        raise HTTPException(status_code=401, detail="firma de PayPal invalida")

    event_type = event.get("event_type", "")
    if event_type not in paypal.PAYMENT_RECEIVED_EVENTS:
        # Verificado pero no es un evento de pago (cancelacion, etc) --
        # se ignora a proposito, ver el docstring de PAYMENT_RECEIVED_EVENTS.
        return

    method, value = paypal.resolve_license_key_lookup(event)
    if not value:
        logger.warning("webhook de PayPal (%s) sin custom_id ni subscription id -- no se puede resolver el cliente", event_type)
        return

    row = db.get_client(value) if method == "license_key" else db.get_client_by_paypal_subscription_id(value)
    if row is None:
        logger.warning("webhook de PayPal (%s) no corresponde a ningun cliente conocido (%s=%s)", event_type, method, value)
        return

    license_key = row["license_key"]
    resource = event.get("resource", {}) or {}
    if method == "license_key" and resource.get("id"):
        # Primer pago (BILLING.SUBSCRIPTION.ACTIVATED): todavia no
        # teniamos el subscription_id guardado si el link se genero
        # fuera de /admin/clients/.../paypal-subscription-link -- se
        # backfillea aca para que los PROXIMOS cobros recurrentes
        # (PAYMENT.SALE.COMPLETED, que solo traen billing_agreement_id)
        # puedan resolver el cliente.
        db.set_paypal_subscription_id(license_key, resource["id"])

    try:
        _extend_expiry(license_key, DEFAULT_PERIOD_DAYS)
    except LookupError:
        return
    db.append_note(license_key, f"PayPal {event_type} -- +{DEFAULT_PERIOD_DAYS} dias")
    logger.info("licencia extendida via webhook de PayPal", extra={"license_key": license_key, "event_type": event_type})


@app.post("/admin/clients/{license_key}/mercadopago-subscription-link", response_model=MercadoPagoLinkOut)
async def mercadopago_subscription_link(license_key: str, payload: MercadoPagoLinkRequest, _: None = Depends(require_admin)):
    """Genera el link de Mercado Pago que le mandas al cliente para que
    apruebe la suscripcion en pesos A TU cuenta. Cuando lo aprueba,
    Mercado Pago factura y dispara el topico subscription_preapproval
    contra /webhooks/mercadopago, que extiende la licencia solo."""
    if db.get_client(license_key) is None:
        raise HTTPException(status_code=404, detail="license_key desconocida -- creala primero con POST /admin/clients")
    if not mercadopago.is_configured():
        raise HTTPException(status_code=503, detail="MERCADOPAGO_ACCESS_TOKEN no configurado en este servidor")
    try:
        preapproval_id, init_point = await mercadopago.create_subscription_approval_link(
            license_key, payload.payer_email, payload.plan_id
        )
    except mercadopago.MercadoPagoError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.set_mercadopago_preapproval_id(license_key, preapproval_id)
    return MercadoPagoLinkOut(preapproval_id=preapproval_id, init_point=init_point)


@app.post("/webhooks/mercadopago", status_code=status.HTTP_204_NO_CONTENT)
async def mercadopago_webhook(request: Request):
    """Mercado Pago le pega aca en cada notificacion (vinculacion de
    suscripcion, cobro recurrente, etc). El cuerpo SOLO trae un id --
    nunca hay que confiar en el resto del payload sin verificar la
    firma primero, y aun verificada, se vuelve a pedir el recurso
    completo a la API de Mercado Pago (fetch_preapproval /
    fetch_authorized_payment) antes de extender nada, en vez de leer el
    status desde el cuerpo del webhook."""
    if not mercadopago.is_configured():
        raise HTTPException(status_code=503, detail="Mercado Pago no esta configurado en este servidor")

    event = await request.json()
    event_type = event.get("type", "")
    data_id = str((event.get("data") or {}).get("id") or "")

    if not data_id or not mercadopago.verify_webhook_signature(dict(request.headers), data_id):
        logger.warning("webhook de Mercado Pago con firma invalida o no verificable -- ignorado")
        raise HTTPException(status_code=401, detail="firma de Mercado Pago invalida")

    if event_type not in mercadopago.PAYMENT_RECEIVED_TOPICS:
        # Verificado pero no es un topico de cobro de suscripcion (un
        # "payment" suelto, etc) -- se ignora a proposito.
        return

    try:
        if event_type == mercadopago.SUBSCRIPTION_LINKED_TOPIC:
            resource = await mercadopago.fetch_preapproval(data_id)
            resource_kind = "preapproval"
            paid = resource.get("status") == "authorized"
        else:
            resource = await mercadopago.fetch_authorized_payment(data_id)
            resource_kind = "authorized_payment"
            paid = resource.get("status") == "processed"
    except mercadopago.MercadoPagoError as exc:
        logger.warning("no se pudo confirmar el recurso de Mercado Pago %s (%s): %s", data_id, event_type, exc)
        return

    if not paid:
        # Firma valida y recurso real, pero todavia no representa un
        # cobro efectivamente recibido (ej: preapproval en "pending") --
        # no se extiende nada.
        return

    method, value = mercadopago.resolve_license_key_lookup(resource, resource_kind)
    if not value:
        logger.warning("webhook de Mercado Pago (%s) sin external_reference ni preapproval id -- no se puede resolver el cliente", event_type)
        return

    row = db.get_client(value) if method == "license_key" else db.get_client_by_mercadopago_preapproval_id(value)
    if row is None:
        logger.warning("webhook de Mercado Pago (%s) no corresponde a ningun cliente conocido (%s=%s)", event_type, method, value)
        return

    license_key = row["license_key"]
    preapproval_id = resource.get("id") if resource_kind == "preapproval" else resource.get("preapproval_id")
    if method == "license_key" and preapproval_id:
        # Backfill para que los proximos cobros recurrentes puedan
        # resolver el cliente aun si en algun caso no trajeran
        # external_reference.
        db.set_mercadopago_preapproval_id(license_key, preapproval_id)

    try:
        _extend_expiry(license_key, DEFAULT_PERIOD_DAYS)
    except LookupError:
        return
    db.append_note(license_key, f"Mercado Pago {event_type} -- +{DEFAULT_PERIOD_DAYS} dias")
    logger.info("licencia extendida via webhook de Mercado Pago", extra={"license_key": license_key, "event_type": event_type})


@app.post("/admin/clients/{license_key}/revoke", response_model=ClientOut)
def revoke_client(license_key: str, _: None = Depends(require_admin)):
    """Corta el acceso YA (pone subscription_expires_at = ahora) -- para
    fraude/chargebacks, no para el vencimiento normal de fin de mes (eso
    ya lo maneja is_org_active() solo, sin tocar este endpoint)."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    db.set_expiry(license_key, _now().isoformat())
    row = db.get_client(license_key)
    return ClientOut(**dict(row))


@app.get("/license/{license_key}/status")
def license_status(license_key: str, response: Response):
    row = db.get_client(license_key)
    now = _now()
    if row is None:
        payload = {"license_key": license_key, "valid": False, "valid_until": None, "checked_at": now.isoformat()}
    else:
        expires_at = datetime.fromisoformat(row["subscription_expires_at"])
        payload = {
            "license_key": license_key,
            "valid": expires_at > now,
            "valid_until": row["subscription_expires_at"],
            "checked_at": now.isoformat(),
        }
    # La firma va en un header (no en el body) para que el body siga
    # siendo JSON plano y facil de loguear/debuggear -- el cliente
    # (backend/shared/license_check.py) lee X-Signature y verifica sobre
    # el body ya parseado con la misma codificacion canonica.
    response.headers["X-Signature"] = sign_payload(payload)
    return payload
