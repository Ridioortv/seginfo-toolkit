"""Integracion con Mercado Pago (Argentina): crear la suscripcion (debito
automatico cada 30 dias, en pesos) que se le manda a cada cliente -- paga a
la cuenta de Mercado Pago del operador -- y verificar los avisos (webhooks)
antes de extender ninguna licencia.

Es la segunda pasarela, al lado de PayPal (app/paypal.py): el cliente elige
cual usar en "Pagos y licencia". PayPal cobra USD 250; Mercado Pago solo
cobra en ARS (en Argentina), asi que el monto en pesos sale de convertir
USD 250 con la cotizacion del dia, EN EL MOMENTO de generar el link.
Ojo: Mercado Pago fija el monto de la suscripcion al crearla; los cobros
siguientes salen por el mismo monto en pesos hasta que se actualice.

Variables de entorno (ver .env.example):
    MP_ACCESS_TOKEN -- Access Token de tu aplicacion en
        https://www.mercadopago.com.ar/developers/panel/app
        (credenciales de prueba mientras probas, de produccion despues)
    MP_WEBHOOK_SECRET -- "Clave secreta" que te da el panel al configurar
        Webhooks (Tus integraciones -> tu app -> Webhooks); opcional
    MP_WEBHOOK_REQUIRE_SIGNATURE -- 1 para rechazar avisos sin firma
    MP_NOTIFICATION_URL -- https://tu-servidor/webhooks/mercadopago
        (se manda en cada suscripcion; tambien podes cargarla en el panel)
    MP_BACK_URL -- a donde vuelve el navegador del cliente despues de pagar
    MP_PRICE_USD -- precio en dolares (default 250)
    MP_FX_URL / MP_FX_FIELD -- API de cotizacion (default dolarapi.com,
        dolar oficial, campo "venta")
    MP_FX_MARGIN_PCT -- recargo sobre la cotizacion (default 0)
    MP_FALLBACK_RATE -- cotizacion a usar si la API de cotizacion falla
        (si no la seteas y la API falla, no se genera el link)

Sin MP_ACCESS_TOKEN, is_configured() es False y los endpoints de Mercado
Pago devuelven 503 en vez de llamar a una API sin credenciales."""
import hashlib
import hmac
import logging
import os
import re
import time

import httpx

logger = logging.getLogger("mercadopago")

def _env(name: str, default: str = "") -> str:
    """Variable de entorno sin espacios ni saltos de linea a los costados (se
    cuelan al pegar valores en el dashboard de Render)."""
    return os.getenv(name, default).strip()


def _env_float(name: str, default: float) -> float:
    """Un numero mal escrito en el dashboard (ej. "250 USD") no debe impedir que
    el servidor arranque: se usa el valor por defecto."""
    try:
        return float(_env(name).replace(",", ".")) if _env(name) else default
    except ValueError:
        return default


MP_ACCESS_TOKEN = _env("MP_ACCESS_TOKEN")
MP_WEBHOOK_SECRET = _env("MP_WEBHOOK_SECRET")
MP_NOTIFICATION_URL = _env("MP_NOTIFICATION_URL")
MP_BACK_URL = _env("MP_BACK_URL") or "https://www.google.com/?sentinelops_subscribed=1"
MP_PRICE_USD = _env_float("MP_PRICE_USD", 250.0)
# SOLO PARA PRUEBAS: con credenciales de prueba, Mercado Pago exige que el
# pagador sea un usuario COMPRADOR de prueba. Si esta variable tiene su email,
# se usa siempre ese pagador (asi nadie tiene que tipearlo en el modal).
# En produccion tiene que estar VACIA.
MP_TEST_PAYER_EMAIL = _env("MP_TEST_PAYER_EMAIL")


def _normalize_payer_email(email: str) -> str:
    """El Usuario de una cuenta de prueba se ve como TESTUSER123 pero su email es
    test_user_123@testuser.com (sin la palabra TESTUSER). Si alguien pego
    test_user_TESTUSER123@testuser.com se corrige solo."""
    return re.sub(r"^test_user_testuser(\d+)@testuser\.com$", r"test_user_\1@testuser.com", email.strip(), flags=re.I)


MP_TEST_PAYER_EMAIL = _normalize_payer_email(MP_TEST_PAYER_EMAIL)
# Mercado Pago documenta que el webhook firmado con la clave secreta del panel
# puede no aplicar a las notificaciones de Suscripciones (las que salen del
# notification_url mandado al crearlas). Por eso, por defecto, una notificacion
# SIN firma se acepta (el estado del cobro se vuelve a pedir a la API, asi que
# no se puede falsificar); una firma presente pero incorrecta siempre se
# rechaza. Con MP_WEBHOOK_REQUIRE_SIGNATURE=1 toda notificacion debe venir firmada.
MP_WEBHOOK_REQUIRE_SIGNATURE = _env("MP_WEBHOOK_REQUIRE_SIGNATURE").lower() in ("1", "true", "yes")
MP_FX_URL = _env("MP_FX_URL") or "https://dolarapi.com/v1/dolares/oficial"
MP_FX_FIELD = _env("MP_FX_FIELD") or "venta"
MP_FX_MARGIN_PCT = _env_float("MP_FX_MARGIN_PCT", 0.0)
MP_FALLBACK_RATE = _env("MP_FALLBACK_RATE")
# Una cotizacion fuera de este rango es basura de la API (un 1 o un 0 cobraria
# 250 pesos en vez de ~400 mil): se descarta antes de crearle un cobro a nadie.
MP_FX_MIN = _env_float("MP_FX_MIN", 100.0)
MP_FX_MAX = _env_float("MP_FX_MAX", 100000.0)
FX_CACHE_SECONDS = 600

_API = "https://api.mercadopago.com"
PERIOD_DAYS = 30
_fx_cache: dict = {"rate": None, "at": 0.0}


class MercadoPagoError(Exception):
    pass


def is_configured() -> bool:
    return bool(MP_ACCESS_TOKEN)


def _headers() -> dict:
    return {"Authorization": f"Bearer {MP_ACCESS_TOKEN}", "Content-Type": "application/json"}


def _raise_for_mp_status(resp: httpx.Response, what: str) -> None:
    if resp.status_code in (401, 403):
        raise MercadoPagoError(
            f"Mercado Pago rechazo el Access Token (HTTP {resp.status_code}) al {what}. Revisa "
            "MP_ACCESS_TOKEN en el servidor (que sea el de la aplicacion correcta y sin espacios)."
        )


def _valid_rate(value) -> float | None:
    try:
        rate = float(str(value).strip().replace(",", "."))
    except (TypeError, ValueError):
        return None
    return rate if MP_FX_MIN <= rate <= MP_FX_MAX else None


async def get_usd_ars_rate(client: httpx.AsyncClient | None = None) -> float:
    """Pesos por dolar. Cache de 10 min; si la API falla o devuelve algo
    fuera de rango usa MP_FALLBACK_RATE; si tampoco hay, MercadoPagoError."""
    now = time.monotonic()
    if _fx_cache["rate"] is not None and now - _fx_cache["at"] < FX_CACHE_SECONDS:
        return _fx_cache["rate"]

    rate = None
    try:
        if client is not None:
            resp = await client.get(MP_FX_URL)
        else:
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.get(MP_FX_URL)
        if resp.status_code == 200:
            rate = _valid_rate(resp.json().get(MP_FX_FIELD))
    except (httpx.HTTPError, ValueError, AttributeError):
        rate = None

    if rate is None:
        rate = _valid_rate(MP_FALLBACK_RATE)
        if rate is None:
            raise MercadoPagoError(
                "no se pudo obtener la cotizacion del dolar y MP_FALLBACK_RATE esta vacia o es invalida "
                "(poné solo el numero, por ejemplo 1300)"
            )
        return rate  # el fallback no se cachea: en cuanto la API vuelva se usa la real

    _fx_cache.update(rate=rate, at=now)
    return rate


def price_ars(rate: float) -> int:
    """USD -> pesos enteros, con el recargo opcional."""
    return round(MP_PRICE_USD * rate * (1 + MP_FX_MARGIN_PCT / 100))


async def _collector_kind(client: httpx.AsyncClient) -> tuple[str, str | None]:
    """Mejor esfuerzo para el diagnostico: ('test'|'real'|'unknown', email de la
    cuenta vendedora SOLO si es de prueba -- el email de una cuenta real no se
    expone). Nunca lanza."""
    try:
        resp = await client.get(f"{_API}/users/me", headers=_headers(), timeout=8)
        if resp.status_code >= 400:
            return "unknown", None
        me = resp.json()
        email = str(me.get("email") or "")
        tags = [str(t) for t in (me.get("tags") or [])]
        if "test_user" in tags or email.lower().endswith("@testuser.com"):
            return "test", email or None
        return "real", None
    except (httpx.HTTPError, ValueError):
        return "unknown", None


async def create_subscription_approval_link(license_key: str, payer_email: str | None = None) -> tuple[str, str, int]:
    """Crea una suscripcion en Mercado Pago (pendiente: el cliente todavia no
    pago) con external_reference=license_key y devuelve (preapproval_id,
    init_point, monto_en_pesos). El cliente abre init_point, elige como pagar
    y autoriza el debito; Mercado Pago cobra y avisa por webhook."""
    if not is_configured():
        raise MercadoPagoError("MP_ACCESS_TOKEN no configurado")

    async with httpx.AsyncClient(timeout=15) as client:
        amount = price_ars(await get_usd_ars_rate(client))
        payload = {
            "reason": "TERO Security - suscripcion mensual",
            "external_reference": license_key,
            "auto_recurring": {
                "frequency": PERIOD_DAYS,
                "frequency_type": "days",
                "transaction_amount": amount,
                "currency_id": "ARS",
            },
            "back_url": MP_BACK_URL,
            "status": "pending",
        }
        if MP_TEST_PAYER_EMAIL:
            logger.warning("MP_TEST_PAYER_EMAIL activo: el pagador de Mercado Pago se fuerza a ese email (solo pruebas)")
            payer_email = MP_TEST_PAYER_EMAIL
        if payer_email:
            payload["payer_email"] = payer_email
        if MP_NOTIFICATION_URL:
            payload["notification_url"] = MP_NOTIFICATION_URL
        resp = await client.post(f"{_API}/preapproval", headers=_headers(), json=payload)
        if resp.status_code == 400 and "User bad request" in resp.text and "payer_email" in payload:
            # Mercado Pago no reconoce ese email como una cuenta suya (por ejemplo
            # el email de login del cliente, que no es de Mercado Pago). Se
            # reintenta sin email: el pagador inicia sesion con su cuenta en el checkout.
            bad_email = payload.pop("payer_email")
            origin = "MP_TEST_PAYER_EMAIL" if MP_TEST_PAYER_EMAIL else "el email del modal"
            logger.warning("Mercado Pago rechazo el payer_email %s (de %s); se reintenta sin email", bad_email, origin)
            retry = await client.post(f"{_API}/preapproval", headers=_headers(), json=payload)
            if retry.status_code >= 400:
                raise MercadoPagoError(
                    f"Mercado Pago no reconoce {bad_email} (de {origin}) como una cuenta suya y sin email tampoco "
                    f"creo la suscripcion ({retry.status_code}). Con credenciales de prueba el email tiene que ser "
                    "exactamente el del COMPRADOR de prueba: entra a mercadopago.com.ar con ese usuario y copia el "
                    "email de su perfil (suele ser test_user_<solo los numeros>@testuser.com, sin la palabra TESTUSER). "
                    "Cargalo en MP_TEST_PAYER_EMAIL (Render)."
                )
            resp = retry
        _raise_for_mp_status(resp, "crear la suscripcion")
        if resp.status_code == 400 and "real or test" in resp.text:
            origin = "MP_TEST_PAYER_EMAIL" if MP_TEST_PAYER_EMAIL else "el email del modal"
            sent = f"{payer_email} (de {origin})" if payer_email else "ninguno"
            kind, seller_email = await _collector_kind(client)
            creds = {"test": "de PRUEBA", "real": "REALES"}.get(kind, "(no se pudo detectar)")
            if seller_email:
                creds += f", cuenta vendedora {seller_email}"
            raise MercadoPagoError(
                "Mercado Pago: cobrador y pagador tienen que ser los dos de prueba o los dos reales. "
                f"Diagnostico: credenciales {creds}; pagador enviado: {sent}. "
                "Con credenciales de prueba, define MP_TEST_PAYER_EMAIL en Render con el email del COMPRADOR de "
                "prueba (test_user_<User ID del comprador>@testuser.com, del mismo pais que la vendedora). "
                "En produccion usa credenciales reales y deja esa variable vacia."
            )
        if resp.status_code >= 400:
            raise MercadoPagoError(f"Mercado Pago rechazo la creacion de la suscripcion: {resp.status_code} {resp.text[:500]}")
        body = resp.json()

    preapproval_id = body.get("id")
    init_point = body.get("init_point")
    if not preapproval_id or not init_point:
        raise MercadoPagoError("la respuesta de Mercado Pago no incluyo id o init_point")
    return str(preapproval_id), str(init_point), amount


async def get_preapproval(preapproval_id: str) -> dict | None:
    """Suscripcion en Mercado Pago (status: pending, authorized, paused,
    cancelled). None si no la conoce (404)."""
    if not is_configured():
        raise MercadoPagoError("MP_ACCESS_TOKEN no configurado")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{_API}/preapproval/{preapproval_id}", headers=_headers())
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        raise MercadoPagoError(f"no se pudo consultar la suscripcion: {resp.status_code} {resp.text[:300]}")
    return resp.json()


async def get_subscription_status(preapproval_id: str) -> str | None:
    body = await get_preapproval(preapproval_id)
    return (str(body.get("status", "")).lower() or None) if body else None


async def get_authorized_payment(authorized_payment_id: str) -> dict | None:
    """Un cobro de la suscripcion (status: scheduled, processed, recycling,
    cancelled). El aviso del webhook solo trae el id: el estado real se
    pregunta siempre a la API, nunca se confia en lo que diga el aviso."""
    if not is_configured():
        raise MercadoPagoError("MP_ACCESS_TOKEN no configurado")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{_API}/authorized_payments/{authorized_payment_id}", headers=_headers())
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        raise MercadoPagoError(f"no se pudo consultar el cobro: {resp.status_code} {resp.text[:300]}")
    return resp.json()


async def cancel_subscription(preapproval_id: str) -> None:
    """Cancela el PROXIMO cobro. El periodo ya pagado sigue corriendo."""
    if not is_configured():
        raise MercadoPagoError("MP_ACCESS_TOKEN no configurado")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.put(
            f"{_API}/preapproval/{preapproval_id}", headers=_headers(), json={"status": "cancelled"}
        )
    # 404 = Mercado Pago ya no la conoce; para el cliente el resultado es el
    # mismo (no se le cobra mas), no es un error.
    if resp.status_code >= 400 and resp.status_code != 404:
        raise MercadoPagoError(f"Mercado Pago rechazo la cancelacion: {resp.status_code} {resp.text[:500]}")


def is_payment_processed(authorized_payment: dict) -> bool:
    """True si el cobro se acredito de verdad. Es lo UNICO que extiende la
    licencia (scheduled/recycling/cancelled no)."""
    if str(authorized_payment.get("status", "")).lower() != "processed":
        return False
    payment = authorized_payment.get("payment") or {}
    pay_status = str(payment.get("status", "")).lower()
    return pay_status in ("", "approved")


def check_webhook_signature(headers: dict, data_id: str) -> str:
    """Devuelve "valid", "invalid" o "unsigned".

    Mercado Pago firma con HMAC-SHA256 (clave = MP_WEBHOOK_SECRET) el texto
    "id:<data.id>;request-id:<x-request-id>;ts:<ts>;" y manda el resultado en
    el header x-signature ("ts=...,v1=..."). "unsigned" = no hay header o no
    hay secreto configurado para poder verificarlo."""
    lower = {k.lower(): v for k, v in headers.items()}
    signature = lower.get("x-signature", "")
    if not signature or not MP_WEBHOOK_SECRET:
        return "unsigned"
    if not data_id:
        return "invalid"
    request_id = lower.get("x-request-id", "")
    parts = dict(p.strip().split("=", 1) for p in signature.split(",") if "=" in p)
    ts, v1 = parts.get("ts", ""), parts.get("v1", "")
    if not ts or not v1:
        return "invalid"
    # Mercado Pago lo calcula con el id en minusculas cuando es alfanumerico.
    normalized_id = data_id.lower() if re.fullmatch(r"[A-Za-z0-9]+", data_id) else data_id
    manifest = f"id:{normalized_id};"
    if request_id:
        manifest += f"request-id:{request_id};"
    manifest += f"ts:{ts};"
    expected = hmac.new(MP_WEBHOOK_SECRET.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    return "valid" if hmac.compare_digest(expected, v1) else "invalid"
