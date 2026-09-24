"""Integracion con Mercado Pago: crear el link de suscripcion (Preapproval)
que se le manda a cada cliente (cobra en ARS, a la cuenta de Mercado Pago
del operador) y verificar la firma de los webhooks antes de extender
ninguna licencia.

Variables de entorno (ver .env.example):
    MERCADOPAGO_ACCESS_TOKEN -- el access token de tu aplicacion en
        https://www.mercadopago.com.ar/developers/panel/app (uno de
        "prueba"/test y otro de "produccion" -- cual uses decide si se
        cobra plata real o no, a diferencia de PayPal no hay una URL
        distinta para sandbox).
    MERCADOPAGO_WEBHOOK_SECRET -- la "clave secreta" que Mercado Pago
        te muestra al configurar el webhook (panel de tu app ->
        Webhooks -> configurar notificaciones). Es lo unico que permite
        distinguir un webhook real de uno inventado por cualquiera.
    MERCADOPAGO_PLAN_ID -- el id del plan de suscripcion (creado una
        vez, ver README.md). Cada cliente NO se suscribe directo a este
        plan (ver el docstring de create_subscription_approval_link
        para el por que) -- se usa solo como referencia de la que este
        servidor copia el monto/frecuencia al crear la suscripcion de
        cada cliente.
    MERCADOPAGO_BACK_URL -- a donde vuelve el navegador del cliente
        despues de aprobar/rechazar en Mercado Pago.

Sin MERCADOPAGO_ACCESS_TOKEN configurado, is_configured() es False y
tanto /admin/clients/{key}/mercadopago-subscription-link como
/webhooks/mercadopago devuelven 503 en vez de intentar llamar a una API
que no tienen con que autenticarse.

Nota sobre la verificacion de firma: Mercado Pago NO tiene un endpoint
tipo "verify-webhook-signature" (a diferencia de PayPal) -- hay que
calcular el HMAC uno mismo. El algoritmo exacto (documentado por
Mercado Pago y usado por sus SDKs oficiales, ver sdk-go) es:
    manifest = f"id:{data_id};request-id:{x_request_id};ts:{ts};"
    firma = hmac_sha256(secret, manifest).hexdigest()
comparado en tiempo constante contra el campo v1 del header
X-Signature (formato "ts=<ts>,v1=<firma>"). data_id se pasa en
minusculas antes de armar el manifest (asi lo hace el SDK oficial de
Go, mercadopago/sdk-go)."""
import hashlib
import hmac
import os

import httpx

MERCADOPAGO_ACCESS_TOKEN = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "")
MERCADOPAGO_WEBHOOK_SECRET = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "")
MERCADOPAGO_PLAN_ID = os.getenv("MERCADOPAGO_PLAN_ID", "")
MERCADOPAGO_BACK_URL = os.getenv("MERCADOPAGO_BACK_URL", "https://www.google.com/?sentinelops_subscribed=1")

BASE_URL = "https://api.mercadopago.com"

# Topicos de notificacion que representan un cobro efectivamente
# vinculado/recibido -- los unicos que disparan una extension de la
# licencia. subscription_preapproval avisa cuando el cliente autoriza
# la suscripcion (primer cobro); subscription_authorized_payment avisa
# en CADA cobro recurrente posterior. El topico "payment" (pagos
# sueltos, no de suscripcion) se ignora a proposito -- no es el flujo
# que usa este servidor.
SUBSCRIPTION_LINKED_TOPIC = "subscription_preapproval"
RECURRING_CHARGE_TOPIC = "subscription_authorized_payment"
PAYMENT_RECEIVED_TOPICS = {SUBSCRIPTION_LINKED_TOPIC, RECURRING_CHARGE_TOPIC}


class MercadoPagoError(Exception):
    pass


def is_configured() -> bool:
    return bool(MERCADOPAGO_ACCESS_TOKEN)


def _headers() -> dict:
    return {"Authorization": f"Bearer {MERCADOPAGO_ACCESS_TOKEN}", "Content-Type": "application/json"}


async def create_subscription_approval_link(
    license_key: str, payer_email: str, plan_id: str | None = None
) -> tuple[str, str]:
    """Crea una suscripcion (Preapproval) en Mercado Pago con los mismos
    terminos del plan de referencia (MERCADOPAGO_PLAN_ID), con
    external_reference=license_key, y devuelve (preapproval_id,
    init_point). El operador manda init_point al cliente; cuando lo
    aprueba (con su propia cuenta/tarjeta, en la pagina de Mercado
    Pago), Mercado Pago factura a la cuenta del operador y dispara el
    webhook subscription_preapproval.

    A proposito NO se manda "preapproval_plan_id" en el POST /preapproval
    de mas abajo -- Mercado Pago exige "card_token_id" (tokenizar la
    tarjeta del lado del servidor) para cualquier suscripcion creada CON
    ese campo ("Suscripcion con plan asociado", ver la documentacion de
    Mercado Pago: "siempre debe crearse con su card_token_id y en status
    Authorized"), lo que rompe el flujo que este servidor necesita (el
    cliente entra el/ella misma su tarjeta en la pagina de Mercado
    Pago, este servidor nunca la toca). En cambio, se lee el plan solo
    para copiar sus terminos (auto_recurring, reason) y se crea una
    "Suscripcion SIN plan asociado" con status=pending -- ese flujo si
    devuelve init_point sin pedir card_token_id."""
    if not is_configured():
        raise MercadoPagoError("MERCADOPAGO_ACCESS_TOKEN no configurado")
    plan_id = plan_id or MERCADOPAGO_PLAN_ID
    if not plan_id:
        raise MercadoPagoError("No hay plan_id (MERCADOPAGO_PLAN_ID vacio y no se paso uno explicito)")

    async with httpx.AsyncClient(timeout=15) as client:
        plan_resp = await client.get(f"{BASE_URL}/preapproval_plan/{plan_id}", headers=_headers())
        if plan_resp.status_code >= 400:
            raise MercadoPagoError(
                f"no se pudo leer el plan {plan_id}: {plan_resp.status_code} {plan_resp.text[:500]}"
            )
        plan = plan_resp.json()
        auto_recurring = plan.get("auto_recurring") or {}

        resp = await client.post(
            f"{BASE_URL}/preapproval",
            headers=_headers(),
            json={
                "external_reference": license_key,
                "payer_email": payer_email,
                "reason": plan.get("reason") or "SentinelOps mensual",
                "back_url": MERCADOPAGO_BACK_URL,
                "status": "pending",
                "auto_recurring": {
                    "frequency": auto_recurring.get("frequency", 30),
                    "frequency_type": auto_recurring.get("frequency_type", "days"),
                    "transaction_amount": auto_recurring.get("transaction_amount"),
                    "currency_id": auto_recurring.get("currency_id", "ARS"),
                },
            },
        )
        if resp.status_code >= 400:
            raise MercadoPagoError(f"Mercado Pago rechazo la creacion de la suscripcion: {resp.status_code} {resp.text[:500]}")
        body = resp.json()

    preapproval_id = body.get("id")
    init_point = body.get("init_point") or body.get("sandbox_init_point")
    if not preapproval_id or not init_point:
        raise MercadoPagoError(f"la respuesta de Mercado Pago no incluyo id/init_point: {body}")
    return preapproval_id, init_point


async def fetch_preapproval(preapproval_id: str) -> dict:
    """Vuelve a pedirle el recurso a Mercado Pago en vez de confiar en
    el cuerpo del webhook (que solo trae el id) -- asi nos aseguramos
    de leer el status real y el external_reference directamente de la
    fuente, autenticados con nuestro propio access token."""
    if not is_configured():
        raise MercadoPagoError("MERCADOPAGO_ACCESS_TOKEN no configurado")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{BASE_URL}/preapproval/{preapproval_id}", headers=_headers())
        if resp.status_code >= 400:
            raise MercadoPagoError(f"no se pudo confirmar la preapproval {preapproval_id}: {resp.status_code} {resp.text[:500]}")
        return resp.json()


async def fetch_authorized_payment(authorized_payment_id: str) -> dict:
    """Idem fetch_preapproval, para un cobro recurrente puntual."""
    if not is_configured():
        raise MercadoPagoError("MERCADOPAGO_ACCESS_TOKEN no configurado")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{BASE_URL}/authorized_payments/{authorized_payment_id}", headers=_headers())
        if resp.status_code >= 400:
            raise MercadoPagoError(f"no se pudo confirmar el cobro {authorized_payment_id}: {resp.status_code} {resp.text[:500]}")
        return resp.json()


def _parse_x_signature(x_signature: str) -> tuple[str, str]:
    """"ts=1704908010,v1=618c853..." -> ("1704908010", "618c853...")."""
    ts, v1 = "", ""
    for part in x_signature.split(","):
        part = part.strip()
        if part.startswith("ts="):
            ts = part[len("ts="):]
        elif part.startswith("v1="):
            v1 = part[len("v1="):]
    return ts, v1


def verify_webhook_signature(headers: dict, data_id: str) -> bool:
    """Verifica localmente la firma de un webhook de Mercado Pago (no
    hay endpoint oficial para delegar esto, a diferencia de PayPal).
    Sin MERCADOPAGO_WEBHOOK_SECRET configurado, devuelve False -- mas
    vale rechazar todo antes que aceptar webhooks sin poder
    verificarlos."""
    if not is_configured() or not MERCADOPAGO_WEBHOOK_SECRET:
        return False

    lower_headers = {k.lower(): v for k, v in headers.items()}
    x_signature = lower_headers.get("x-signature", "")
    x_request_id = lower_headers.get("x-request-id", "")
    if not x_signature:
        return False

    ts, v1 = _parse_x_signature(x_signature)
    if not ts or not v1:
        return False

    manifest = f"id:{data_id.lower()};request-id:{x_request_id};ts:{ts};"
    expected = hmac.new(MERCADOPAGO_WEBHOOK_SECRET.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)


def resolve_license_key_lookup(resource: dict, resource_kind: str) -> tuple[str, str]:
    """De un recurso YA reconfirmado con la API (preapproval o
    authorized_payment -- resource_kind es cual de los dos, nunca se
    adivina del cuerpo del webhook sin verificar), devuelve (metodo,
    valor) para encontrar el cliente. external_reference es la
    license_key seteada al crear la suscripcion -- viaja tanto en la
    preapproval como en cada authorized_payment que genera. Si por lo
    que sea no vino (cuenta vieja, etc), se cae al id de la preapproval
    como respaldo (resource["id"] si resource_kind=="preapproval",
    resource["preapproval_id"] si resource_kind=="authorized_payment")."""
    external_reference = resource.get("external_reference")
    if external_reference:
        return "license_key", external_reference
    if resource_kind == "preapproval":
        preapproval_id = resource.get("id")
    else:
        preapproval_id = resource.get("preapproval_id")
    return "mercadopago_preapproval_id", preapproval_id or ""
