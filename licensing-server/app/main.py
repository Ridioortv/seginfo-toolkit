"""Servidor central de licencias de TERO Security.

Este servicio NO se distribuye a los clientes (no va dentro del .rar) --
lo aloja el operador (ver licensing-server/README.md para donde y como
desplegarlo) y es la fuente de verdad de que organizacion tiene la
suscripcion al dia. Cada instalacion on-prem de un cliente (su
auth-service) lo consulta periodicamente via backend/shared/license_check.py
y cachea localmente la respuesta -- ver el razonamiento completo en ese
modulo y en Organization.subscription_expires_at (backend/services/auth-service/app/models.py).

Autenticacion: los endpoints /admin/* (crear/extender/revocar un
cliente, o generar un link de suscripcion de PayPal)
requieren `Authorization: Bearer <ADMIN_TOKEN>` -- son para uso
exclusivo del operador. El webhook de pago (/webhooks/paypal) es la
excepcion: no lleva ese token (PayPal no lo manda), se autentica solo
con su propia firma y llama internamente a la misma logica que usa /admin/.../extend. El
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

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
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


app = FastAPI(title="TERO Security Licensing Server", version="0.1.0", lifespan=lifespan)


@app.exception_handler(httpx.HTTPError)
async def _gateway_http_error(request: Request, exc: httpx.HTTPError):
    """Cualquier fallo de red/HTTP al hablar con PayPal o Mercado Pago que no
    se haya traducido antes: 502 con un mensaje util (y en el log), en vez de
    un "Internal Server Error" mudo."""
    logger.warning("fallo al hablar con la pasarela de pago: %s", exc)
    return JSONResponse(
        status_code=502,
        content={"detail": f"no se pudo hablar con la pasarela de pago ({type(exc).__name__}). Intenta de nuevo en un momento."},
    )


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


class PaypalPublicLinkRequest(BaseModel):
    payer_email: str | None = Field(default=None, description="Opcional: precarga el email en el checkout de PayPal")


class PaypalCancelOut(BaseModel):
    cancelled: bool
    valid_until: str


class MercadoPagoLinkRequest(BaseModel):
    payer_email: str | None = Field(
        default=None, max_length=254, description="Opcional: email de la cuenta de Mercado Pago del pagador"
    )


class MercadoPagoLinkOut(BaseModel):
    subscription_id: str
    approval_url: str
    amount_ars: int


class LicenseHistoryOut(BaseModel):
    notes: str


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


# Estados (de cada pasarela) en los que una suscripcion ya esta, o esta por estar, cobrando.
_LIVE_STATES = {"paypal": {"ACTIVE", "APPROVED"}, "mercadopago": {"authorized", "paused"}}
# Estados de un link que se creo pero el cliente todavia no aprobo.
_PENDING_STATES = {"paypal": {"APPROVAL_PENDING"}, "mercadopago": {"pending"}}
_GATEWAY_NAMES = {"paypal": "PayPal", "mercadopago": "Mercado Pago"}


def _gateway_errors() -> tuple:
    """Errores al hablar con una pasarela. Se arma al usarlo (no al importar)
    para que siempre refiera a las clases vigentes de cada modulo."""
    return (paypal.PayPalError, mercadopago.MercadoPagoError, httpx.HTTPError)


def _gateway_configured(gateway: str) -> bool:
    return paypal.is_configured() if gateway == "paypal" else mercadopago.is_configured()


async def _gateway_status(gateway: str, external_id: str) -> str | None:
    if gateway == "paypal":
        return await paypal.get_subscription_status(external_id)
    return await mercadopago.get_subscription_status(external_id)


async def _gateway_cancel(gateway: str, external_id: str) -> None:
    if gateway == "paypal":
        await paypal.cancel_subscription(external_id)
    else:
        await mercadopago.cancel_subscription(external_id)


def _client_for_subscription(gateway: str, external_id: str):
    """Cliente al que pertenece una suscripcion. Se busca primero en la tabla de
    TODAS las suscripciones (un cobro puede llegar de un link que no es el ultimo
    que se genero) y, por compatibilidad, en la columna de `clients`."""
    if gateway == "paypal":
        row = db.get_client_by_paypal_subscription_id(external_id)
    else:
        row = db.get_client_by_mp_preapproval_id(external_id)
    if row is None:
        sub = db.get_subscription(gateway, external_id)
        if sub is not None:
            row = db.get_client(sub["license_key"])
    return row


async def _refuse_if_subscription_already_active(row, requested: str = "") -> None:
    """Evita el doble cobro: si esta licencia ya tiene una suscripcion ACTIVA
    en PayPal O en Mercado Pago (cualquiera de las que se hayan creado, no solo
    la ultima), un link nuevo crearia otra y el cliente pagaria dos veces por mes.
    Para cambiar de tarjeta/cuenta o de pasarela hay que cancelar la actual antes.

    `requested` es la pasarela para la que se pide el link ("paypal" o
    "mercadopago"). Una pasarela sin configurar, o la OTRA pasarela si falla su
    consulta (credenciales vencidas, caida), no se puede verificar y se saltea
    con un aviso en el log: un PayPal roto no debe impedir pagar con Mercado Pago
    (y al reves). Si falla la consulta de la MISMA pasarela, se corta con 502:
    el link tampoco se podria crear."""
    for sub in db.list_subscriptions(row["license_key"], statuses=("pending", "active")):
        gateway, external_id = sub["gateway"], sub["external_id"]
        if not _gateway_configured(gateway):
            continue
        try:
            state = await _gateway_status(gateway, external_id)
        except _gateway_errors() as exc:
            if requested == gateway:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            logger.warning("no se pudo verificar la suscripcion de %s (se omite el chequeo): %s", _GATEWAY_NAMES[gateway], exc)
            continue
        if state in _LIVE_STATES[gateway]:
            raise HTTPException(
                status_code=409,
                detail=f"Esta licencia ya tiene una suscripcion de {_GATEWAY_NAMES[gateway]} activa. Si queres cambiar la forma de pago, cancela la suscripcion actual primero.",
            )
        if state not in _PENDING_STATES[gateway]:
            # Cancelada / vencida / desconocida para la pasarela: ya no cobra.
            db.set_subscription_status(gateway, external_id, "cancelled")


async def _cancel_previous_pending(license_key: str, keep_gateway: str, keep_id: str) -> None:
    """Al generar un link nuevo, cancela los links ANTERIORES de esa licencia que
    el cliente todavia no aprobo: si no, siguen siendo pagables y se puede pagar
    dos veces (dos pestanas, un link viejo en el mail). Es "mejor esfuerzo": si una
    pasarela falla no se frena el link nuevo, solo queda en el log y en el
    historial; y si algun link viejo igual se paga, la regla de "una sola
    suscripcion activa" (ver _claim_active_slot) cancela la repetida."""
    for sub in db.list_subscriptions(license_key, statuses=("pending",)):
        gateway, external_id = sub["gateway"], sub["external_id"]
        if (gateway, external_id) == (keep_gateway, keep_id) or not _gateway_configured(gateway):
            continue
        try:
            state = await _gateway_status(gateway, external_id)
            if state in _PENDING_STATES[gateway]:
                await _gateway_cancel(gateway, external_id)
                db.append_note(
                    license_key,
                    f"{_GATEWAY_NAMES[gateway]}: link de pago anterior ({external_id}) cancelado porque se genero uno nuevo",
                )
                db.set_subscription_status(gateway, external_id, "cancelled")
            elif state not in _LIVE_STATES[gateway]:
                db.set_subscription_status(gateway, external_id, "cancelled")
        except _gateway_errors() as exc:
            logger.warning("no se pudo cancelar el link anterior %s de %s: %s", external_id, _GATEWAY_NAMES[gateway], exc)
            db.append_note(
                license_key,
                f"{_GATEWAY_NAMES[gateway]}: no se pudo cancelar el link de pago anterior ({external_id}); si se paga, la repetida se cancela sola",
            )


async def _claim_active_slot(license_key: str, gateway: str, external_id: str) -> bool:
    """Una licencia tiene UNA suscripcion activa. Devuelve True si esta es la
    activa (y entonces sus cobros extienden la licencia). Devuelve False si ya
    habia OTRA activa: esta es una repetida (dos links pagados), asi que se la
    cancela en la pasarela, se la marca `duplicate` y se deja una nota para
    devolver ese pago -- sus cobros NO extienden nada.

    Antes de declarar repetida se verifica en la pasarela que la otra siga viva
    (el cliente pudo cancelarla por su cuenta); si esa consulta falla, el error
    sube y el aviso (webhook) se reintenta mas tarde en vez de adivinar."""
    db.add_subscription(license_key, gateway, external_id)
    for _ in range(3):
        if db.claim_active_subscription(license_key, gateway, external_id):
            return True
        mine = db.get_subscription(gateway, external_id)
        if mine is not None and mine["status"] == "duplicate":
            return False
        stale = False
        for other in db.list_subscriptions(license_key, statuses=("active",)):
            if (other["gateway"], other["external_id"]) == (gateway, external_id):
                continue
            if not _gateway_configured(other["gateway"]):
                continue
            state = await _gateway_status(other["gateway"], other["external_id"])
            if state not in _LIVE_STATES[other["gateway"]]:
                db.set_subscription_status(other["gateway"], other["external_id"], "cancelled")
                stale = True
        if not stale:
            break
    db.set_subscription_status(gateway, external_id, "duplicate")
    name = _GATEWAY_NAMES[gateway]
    cancelled_note = "se cancelo automaticamente"
    try:
        await _gateway_cancel(gateway, external_id)
    except _gateway_errors() as exc:
        logger.warning("no se pudo cancelar la suscripcion repetida %s de %s: %s", external_id, name, exc)
        cancelled_note = "NO se pudo cancelar sola: cancelala a mano en la pasarela"
    db.append_note(
        license_key,
        f"{name}: la suscripcion {external_id} se aprobo estando ya activa otra -- {cancelled_note}; "
        "sus cobros NO extienden la licencia. Si ya cobro algo, devolver ese pago al cliente",
    )
    return False


@app.post("/admin/clients/{license_key}/paypal-subscription-link", response_model=PaypalLinkOut)
async def paypal_subscription_link(license_key: str, payload: PaypalLinkRequest, _: None = Depends(require_admin)):
    """Genera el link de PayPal que le mandas al cliente para que apruebe
    la suscripcion de $250/30 dias A TU cuenta de PayPal. Cuando lo
    aprueba, PayPal factura y dispara BILLING.SUBSCRIPTION.ACTIVATED
    contra /webhooks/paypal, que extiende la licencia solo."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida -- creala primero con POST /admin/clients")
    if not paypal.is_configured():
        raise HTTPException(status_code=503, detail="PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET no configurados en este servidor")
    await _refuse_if_subscription_already_active(row, "paypal")
    try:
        subscription_id, approval_url = await paypal.create_subscription_approval_link(license_key, payload.plan_id)
    except paypal.PayPalError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.set_paypal_subscription_id(license_key, subscription_id)
    await _cancel_previous_pending(license_key, "paypal", subscription_id)
    return PaypalLinkOut(subscription_id=subscription_id, approval_url=approval_url)


# /webhooks/billing es un alias: el dashboard de PayPal rechaza ("Please enter a
# valid url") algunas URLs de webhook que contienen la palabra "paypal".
@app.post("/webhooks/billing", status_code=status.HTTP_204_NO_CONTENT)
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
    if event_type not in paypal.PAYMENT_RECEIVED_EVENTS and event_type not in paypal.LINK_EVENTS:
        # Verificado pero no es un evento de pago ni de vinculacion
        # (cancelacion, etc) -- se ignora a proposito, ver el docstring de
        # PAYMENT_RECEIVED_EVENTS.
        return

    # Idempotencia: PayPal reintenta si no recibe 2xx a tiempo; sin esto cada
    # reintento de un pago extenderia la licencia otros 30 dias.
    event_id = event.get("id")
    claim_key = f"paypal:{event_id}" if event_id else None
    if claim_key and not db.claim_event(claim_key):
        logger.info("webhook de PayPal repetido (%s) -- ignorado", event_id)
        return

    # El claim se toma ANTES de saber si el evento se pudo aplicar (para
    # deduplicar reintentos concurrentes), asi que si NO se aplica -- cliente
    # sin resolver o un error -- hay que soltarlo; si no, el reintento de
    # PayPal seria descartado como "repetido" y el pago nunca se acreditaria.
    applied = False
    try:
        applied = await _apply_paypal_event(event, event_type)
    except (paypal.PayPalError, mercadopago.MercadoPagoError) as exc:
        # 502 (no 2xx) para que PayPal reintente mas tarde.
        logger.warning("no se pudo consultar a la pasarela de pago: %s", exc)
        raise HTTPException(status_code=502, detail="no se pudo consultar a la pasarela de pago -- reintentar") from exc
    finally:
        if claim_key and not applied:
            try:
                db.release_event(claim_key)
            except Exception:  # noqa: BLE001 -- no tapar el error original
                logger.exception("no se pudo liberar el claim del evento %s", event_id)
    if not applied and event_type in paypal.PAYMENT_RECEIVED_EVENTS:
        # 409 (no 2xx) para que PayPal reintente: el mapeo cliente<->suscripcion
        # puede completarse con BILLING.SUBSCRIPTION.ACTIVATED, que no tiene
        # orden garantizado respecto de PAYMENT.SALE.COMPLETED.
        raise HTTPException(status_code=409, detail="evento de pago sin cliente resuelto -- reintentar")


async def _apply_paypal_event(event: dict, event_type: str) -> bool:
    """Aplica un evento de PayPal ya verificado. Devuelve True si el evento
    quedo aplicado (o no requiere accion); False si no se pudo resolver el
    cliente o la licencia."""
    method, value = paypal.resolve_license_key_lookup(event)
    if not value:
        logger.warning("webhook de PayPal (%s) sin custom_id ni subscription id -- no se puede resolver el cliente", event_type)
        return False

    row = db.get_client(value) if method == "license_key" else _client_for_subscription("paypal", value)
    if row is None:
        logger.warning("webhook de PayPal (%s) no corresponde a ningun cliente conocido (%s=%s)", event_type, method, value)
        return False

    license_key = row["license_key"]
    resource = event.get("resource", {}) or {}
    # Id de la suscripcion de este evento: BILLING.SUBSCRIPTION.* lo trae en
    # resource.id; los cobros (PAYMENT.SALE.*) en billing_agreement_id.
    is_subscription_event = event_type.startswith("BILLING.SUBSCRIPTION")
    if is_subscription_event:
        subscription_id = str(resource.get("id") or "")
    else:
        subscription_id = str(resource.get("billing_agreement_id") or row["paypal_subscription_id"] or "")
    if method == "license_key" and is_subscription_event and subscription_id:
        # Primer pago (BILLING.SUBSCRIPTION.ACTIVATED): todavia no
        # teniamos el subscription_id guardado si el link se genero
        # fuera de /admin/clients/.../paypal-subscription-link -- se
        # backfillea aca para que los PROXIMOS cobros recurrentes
        # (PAYMENT.SALE.COMPLETED, que solo traen billing_agreement_id)
        # puedan resolver el cliente.
        db.set_paypal_subscription_id(license_key, subscription_id)

    # Una licencia tiene UNA suscripcion activa: si esta es una repetida (se
    # pagaron dos links), ya quedo cancelada y anotada, y no extiende nada.
    holds_slot = await _claim_active_slot(license_key, "paypal", subscription_id) if subscription_id else True

    if event_type in paypal.LINK_EVENTS:
        # Solo vincula (arriba). El cobro llega en PAYMENT.SALE.COMPLETED.
        if holds_slot:
            db.append_note(license_key, "PayPal: suscripcion aprobada por el cliente")
        return True

    if not holds_slot:
        db.append_note(
            license_key,
            f"PayPal {event_type}: cobro de la suscripcion repetida {subscription_id} -- NO se extendio la licencia; devolver ese pago al cliente",
        )
        return True

    try:
        _extend_expiry(license_key, DEFAULT_PERIOD_DAYS)
    except LookupError:
        return False
    # La licencia YA quedo extendida: de aca en adelante nada puede soltar el
    # claim (un reintento duplicaria los 30 dias). La nota es solo bitacora.
    try:
        db.append_note(license_key, f"PayPal {event_type} -- +{DEFAULT_PERIOD_DAYS} dias")
    except Exception:  # noqa: BLE001
        logger.exception("no se pudo anotar la extension de la licencia %s", license_key)
    logger.info("licencia extendida via webhook de PayPal", extra={"license_key": license_key, "event_type": event_type})
    return True


@app.get("/license/{license_key}/history", response_model=LicenseHistoryOut)
def license_history(license_key: str):
    """Autoservicio de solo lectura -- devuelve el historial de eventos
    de esta licencia (pagos confirmados, cancelaciones, renovaciones a
    mano) tal como se van acumulando en notes (ver db.append_note, se
    acota solo a los ultimos 50 renglones). Publico a proposito, igual
    que el resto de /license/{license_key}/... -- son las mismas notas
    que ya devolvia GET /admin/clients (ahi protegidas con
    ADMIN_TOKEN), asi que exponerlas sin ese token no abre nada nuevo
    mas alla de lo que la propia license_key ya podia ver/hacer."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    return LicenseHistoryOut(notes=row["notes"] or "")


@app.post("/license/{license_key}/paypal/subscription-link", response_model=PaypalLinkOut)
async def paypal_public_subscription_link(license_key: str, payload: PaypalPublicLinkRequest):
    """Autoservicio (publico a proposito, igual que el resto de
    /license/{license_key}/...: se autentica solo con conocer la license_key).
    Lo llama la instalacion on-prem cuando el login queda bloqueado por falta
    de pago, o desde la pantalla de Facturacion, para ofrecer el link de
    PayPal de la suscripcion de USD 250 cada 30 dias."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    if not paypal.is_configured():
        raise HTTPException(status_code=503, detail="PayPal no esta configurado en este servidor")
    await _refuse_if_subscription_already_active(row, "paypal")
    try:
        subscription_id, approval_url = await paypal.create_subscription_approval_link(
            license_key, None, payload.payer_email
        )
    except paypal.PayPalError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.set_paypal_subscription_id(license_key, subscription_id)
    await _cancel_previous_pending(license_key, "paypal", subscription_id)
    logger.info("link de pago de PayPal generado (autoservicio)", extra={"license_key": license_key})
    return PaypalLinkOut(subscription_id=subscription_id, approval_url=approval_url)


_CANCEL_NOTES = {
    "paypal": "PayPal: suscripcion cancelada por el cliente -- no se renueva mas, el periodo pagado sigue corriendo hasta que venza",
    "mercadopago": "Mercado Pago: suscripcion cancelada por el cliente -- no se renueva mas, el periodo pagado sigue corriendo hasta que venza",
}


async def _cancel_license_subscriptions(license_key: str, gateway: str | None = None) -> None:
    """Cancela TODAS las suscripciones vivas (pendientes o activas) de la
    licencia, no solo la ultima: si quedara alguna, seguiria cobrando todos los
    meses sin que nadie la viera. `gateway` limita a una sola pasarela."""
    for sub in db.list_subscriptions(license_key, statuses=("pending", "active"), gateway=gateway):
        sub_gateway, external_id = sub["gateway"], sub["external_id"]
        if not _gateway_configured(sub_gateway):
            continue
        try:
            await _gateway_cancel(sub_gateway, external_id)
        except (paypal.PayPalError, mercadopago.MercadoPagoError) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        db.set_subscription_status(sub_gateway, external_id, "cancelled")
        db.append_note(license_key, _CANCEL_NOTES[sub_gateway])


@app.post("/license/{license_key}/paypal/cancel-subscription", response_model=PaypalCancelOut)
async def paypal_cancel_subscription(license_key: str):
    """Autoservicio del cliente: corta el PROXIMO cobro de PayPal. El periodo
    ya pagado sigue corriendo hasta subscription_expires_at (no se toca)."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    if not db.list_subscriptions(license_key, gateway="paypal"):
        raise HTTPException(status_code=404, detail="esta licencia no tiene ninguna suscripcion de PayPal vinculada")
    if not paypal.is_configured():
        raise HTTPException(status_code=503, detail="PayPal no esta configurado en este servidor")
    await _cancel_license_subscriptions(license_key, "paypal")
    row = db.get_client(license_key)
    return PaypalCancelOut(cancelled=True, valid_until=row["subscription_expires_at"])


@app.post("/license/{license_key}/mercadopago/subscription-link", response_model=MercadoPagoLinkOut)
async def mercadopago_public_subscription_link(license_key: str, payload: MercadoPagoLinkRequest):
    """Autoservicio (publico a proposito, igual que el de PayPal: se
    autentica solo con conocer la license_key). Genera el link de la
    suscripcion de Mercado Pago (debito cada 30 dias, en pesos: USD 250
    convertidos con la cotizacion del dia)."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    if not mercadopago.is_configured():
        raise HTTPException(status_code=503, detail="Mercado Pago no esta configurado en este servidor")
    await _refuse_if_subscription_already_active(row, "mercadopago")
    try:
        preapproval_id, init_point, amount = await mercadopago.create_subscription_approval_link(
            license_key, payload.payer_email
        )
    except mercadopago.MercadoPagoError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.set_mp_preapproval_id(license_key, preapproval_id)
    await _cancel_previous_pending(license_key, "mercadopago", preapproval_id)
    logger.info("link de pago de Mercado Pago generado (autoservicio)", extra={"license_key": license_key})
    return MercadoPagoLinkOut(subscription_id=preapproval_id, approval_url=init_point, amount_ars=amount)


@app.post("/license/{license_key}/cancel-subscription", response_model=PaypalCancelOut)
async def cancel_any_subscription(license_key: str):
    """Autoservicio del cliente: corta el PROXIMO cobro, sea cual sea la
    pasarela con la que pago (PayPal y/o Mercado Pago). El periodo ya pagado
    sigue corriendo hasta subscription_expires_at (no se toca)."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    if not db.list_subscriptions(license_key):
        raise HTTPException(status_code=404, detail="esta licencia no tiene ninguna suscripcion vinculada")
    # Se cancelan TODAS las vivas, de cualquier pasarela. Solo si hay alguna viva
    # y NINGUNA se puede cancelar (pasarela sin configurar) se corta con 503.
    live = db.list_subscriptions(license_key, statuses=("pending", "active"))
    if live and not any(_gateway_configured(sub["gateway"]) for sub in live):
        raise HTTPException(status_code=503, detail=f"{_GATEWAY_NAMES[live[0]['gateway']]} no esta configurado en este servidor")
    await _cancel_license_subscriptions(license_key)
    row = db.get_client(license_key)
    return PaypalCancelOut(cancelled=True, valid_until=row["subscription_expires_at"])


@app.post("/webhooks/mercadopago", status_code=status.HTTP_204_NO_CONTENT)
async def mercadopago_webhook(request: Request):
    """Mercado Pago avisa aca de cada cambio en las suscripciones. Publico por
    definicion (no manda tu ADMIN_TOKEN): se protege verificando la firma
    x-signature, y ademas el estado del cobro SIEMPRE se vuelve a pedir a la
    API de Mercado Pago -- el aviso solo trae un id, nunca se confia en su
    contenido. Solo un cobro 'processed' extiende la licencia."""
    if not mercadopago.is_configured():
        raise HTTPException(status_code=503, detail="Mercado Pago no esta configurado en este servidor")

    try:
        body = await request.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    data_id = str(request.query_params.get("data.id") or data.get("id") or "")
    event_type = str(request.query_params.get("type") or body.get("type") or body.get("topic") or "")

    signature = mercadopago.check_webhook_signature(dict(request.headers), data_id)
    if signature == "invalid" or (signature == "unsigned" and mercadopago.MP_WEBHOOK_REQUIRE_SIGNATURE):
        logger.warning("webhook de Mercado Pago con firma invalida o ausente (%s) -- ignorado", signature)
        raise HTTPException(status_code=401, detail="firma de Mercado Pago invalida")
    if not data_id:
        return
    if signature == "unsigned":
        logger.info("webhook de Mercado Pago sin firma verificable: se confia solo en el estado que devuelve su API")

    try:
        if event_type == "subscription_authorized_payment":
            applied = await _apply_mp_authorized_payment(data_id)
            if not applied:
                # 409 (no 2xx) para que Mercado Pago reintente: el cobro puede
                # llegar antes de que quede vinculado el cliente.
                raise HTTPException(status_code=409, detail="cobro sin cliente resuelto -- reintentar")
        elif event_type in ("subscription_preapproval", "preapproval"):
            await _apply_mp_preapproval(data_id)
    except (mercadopago.MercadoPagoError, paypal.PayPalError) as exc:
        # 502 para que Mercado Pago reintente mas tarde.
        logger.warning("no se pudo consultar a Mercado Pago: %s", exc)
        raise HTTPException(status_code=502, detail="no se pudo consultar a Mercado Pago -- reintentar") from exc
    # Cualquier otro tipo (payment, etc.) se ignora a proposito.


async def _apply_mp_authorized_payment(authorized_payment_id: str) -> bool:
    """True si no hay nada mas que hacer (cobro aplicado, o todavia no
    acreditado: llegara otro aviso); False si el cobro esta acreditado pero no
    se pudo resolver de que cliente es."""
    ap = await mercadopago.get_authorized_payment(authorized_payment_id)
    if ap is None:
        logger.warning("cobro %s desconocido para Mercado Pago -- ignorado", authorized_payment_id)
        return True
    if not mercadopago.is_payment_processed(ap):
        return True  # scheduled/recycling/cancelled: no se acredito (todavia)

    preapproval_id = str(ap.get("preapproval_id") or "")
    row = _client_for_subscription("mercadopago", preapproval_id) if preapproval_id else None
    if row is None and preapproval_id:
        # Suscripcion creada fuera de nuestro endpoint (o id aun sin guardar):
        # external_reference es literalmente la license_key.
        pre = await mercadopago.get_preapproval(preapproval_id)
        license_key = str((pre or {}).get("external_reference") or "")
        row = db.get_client(license_key) if license_key else None
        if row is not None:
            db.set_mp_preapproval_id(row["license_key"], preapproval_id)
    if row is None:
        logger.warning("cobro de Mercado Pago %s no corresponde a ningun cliente conocido", authorized_payment_id)
        return False

    license_key = row["license_key"]
    # Idempotencia: Mercado Pago reintenta y manda varios avisos por cobro.
    claim_key = f"mercadopago:authorized_payment:{authorized_payment_id}"
    if not db.claim_event(claim_key):
        logger.info("aviso de Mercado Pago repetido (%s) -- ignorado", authorized_payment_id)
        return True
    applied = False
    try:
        # Una licencia tiene UNA suscripcion activa: el cobro de una repetida
        # (dos links pagados) no extiende nada -- ya quedo cancelada y anotada.
        if preapproval_id and not await _claim_active_slot(license_key, "mercadopago", preapproval_id):
            applied = True
            db.append_note(
                license_key,
                f"Mercado Pago cobro {authorized_payment_id} de la suscripcion repetida {preapproval_id} -- NO se extendio la licencia; devolver ese pago al cliente",
            )
            return True
        _extend_expiry(license_key, DEFAULT_PERIOD_DAYS)
        applied = True
    except LookupError:
        return False
    finally:
        if not applied:
            try:
                db.release_event(claim_key)
            except Exception:  # noqa: BLE001 -- no tapar el error original
                logger.exception("no se pudo liberar el claim %s", claim_key)
    # La licencia YA quedo extendida: la nota es solo bitacora.
    try:
        db.append_note(license_key, f"Mercado Pago cobro {authorized_payment_id} -- +{DEFAULT_PERIOD_DAYS} dias")
    except Exception:  # noqa: BLE001
        logger.exception("no se pudo anotar la extension de la licencia %s", license_key)
    logger.info("licencia extendida via webhook de Mercado Pago", extra={"license_key": license_key})
    return True


async def _apply_mp_preapproval(preapproval_id: str) -> None:
    """Cambio de estado de la suscripcion: solo vincula (backfill del id) y
    deja constancia. NO extiende nada -- el cobro llega aparte."""
    pre = await mercadopago.get_preapproval(preapproval_id)
    if pre is None:
        return
    license_key = str(pre.get("external_reference") or "")
    row = db.get_client(license_key) if license_key else None
    if row is None:
        logger.warning("suscripcion de Mercado Pago %s sin cliente conocido", preapproval_id)
        return
    status_now = str(pre.get("status", "")).lower()
    holds_slot = True
    if status_now == "authorized":
        # Si ya habia otra suscripcion activa para esta licencia, esta es una
        # repetida: se cancela y se anota (ver _claim_active_slot).
        holds_slot = await _claim_active_slot(license_key, "mercadopago", preapproval_id)
        if holds_slot and row["mp_preapproval_id"] != preapproval_id:
            db.set_mp_preapproval_id(license_key, preapproval_id)
    elif status_now == "cancelled":
        db.set_subscription_status("mercadopago", preapproval_id, "cancelled")
    claim_key = f"mercadopago:preapproval:{preapproval_id}:{status_now}"
    if status_now in ("authorized", "cancelled", "paused") and db.claim_event(claim_key) and holds_slot:
        labels = {
            "authorized": "suscripcion aprobada por el cliente",
            "cancelled": "suscripcion cancelada",
            "paused": "suscripcion pausada",
        }
        db.append_note(license_key, f"Mercado Pago: {labels[status_now]}")


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
