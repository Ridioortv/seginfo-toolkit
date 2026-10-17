"""Tests del cobro por Mercado Pago del servidor de licencias (sin tocar la
red: las llamadas a la API se reemplazan por dobles o por httpx.MockTransport).
Correr desde licensing-server/:
    python -m pytest -q tests"""
import hashlib
import hmac
import os
import tempfile
from datetime import datetime, timedelta

import httpx
import pytest

_tmp = tempfile.mkdtemp(prefix="lic-mp-test-")
os.environ["ADMIN_TOKEN"] = "test-admin-token"
os.environ["LICENSING_DB_PATH"] = os.path.join(_tmp, "t.db")
os.environ.pop("DATABASE_URL", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import db, main, mercadopago as mp, paypal  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
SECRET = "mp-test-secret"


@pytest.fixture()
def client(monkeypatch):
    with TestClient(main.app) as c:
        monkeypatch.setattr(mp, "MP_ACCESS_TOKEN", "token")
        monkeypatch.setattr(mp, "MP_WEBHOOK_SECRET", SECRET)
        monkeypatch.setattr(mp, "_fx_cache", {"rate": None, "at": 0.0})
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_ID", "id")
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_SECRET", "secret")
        yield c


def _new_client(c, key, days=1):
    r = c.post("/admin/clients", headers=ADMIN, json={"org_name": "ACME", "license_key": key, "days": days})
    assert r.status_code == 201


def _expiry(key):
    return datetime.fromisoformat(db.get_client(key)["subscription_expires_at"])


def _signed_post(c, data_id, event_type="subscription_authorized_payment", secret=SECRET, request_id="req-1"):
    ts = "1700000000"
    sid = data_id.lower() if data_id.isalnum() else data_id  # como lo firma Mercado Pago
    manifest = f"id:{sid};request-id:{request_id};ts:{ts};"
    v1 = hmac.new(secret.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    return c.post(
        f"/webhooks/mercadopago?data.id={data_id}&type={event_type}",
        json={"type": event_type, "data": {"id": data_id}},
        headers={"x-signature": f"ts={ts},v1={v1}", "x-request-id": request_id},
    )


def _fake_payment(monkeypatch, payments):
    async def _get(ap_id):
        return payments.get(ap_id)

    monkeypatch.setattr(mp, "get_authorized_payment", _get)


def _processed(preapproval_id):
    return {"status": "processed", "preapproval_id": preapproval_id, "payment": {"status": "approved"}}


# --- link ---------------------------------------------------------------

def test_public_link_creates_subscription_and_links_it(client, monkeypatch):
    _new_client(client, "k-mp-link")
    seen = {}

    async def fake_create(license_key, payer_email=None):
        seen.update(license_key=license_key, payer_email=payer_email)
        return "PRE1", "https://mp.test/checkout", 375000

    monkeypatch.setattr(mp, "create_subscription_approval_link", fake_create)
    r = client.post("/license/k-mp-link/mercadopago/subscription-link", json={"payer_email": "a@b.com"})
    assert r.status_code == 200
    assert r.json() == {"subscription_id": "PRE1", "approval_url": "https://mp.test/checkout", "amount_ars": 375000}
    assert seen == {"license_key": "k-mp-link", "payer_email": "a@b.com"}
    assert db.get_client("k-mp-link")["mp_preapproval_id"] == "PRE1"


def test_link_503_when_not_configured(client, monkeypatch):
    _new_client(client, "k-mp-503")
    monkeypatch.setattr(mp, "MP_ACCESS_TOKEN", "")
    assert client.post("/license/k-mp-503/mercadopago/subscription-link", json={}).status_code == 503


def test_link_404_unknown_license(client):
    assert client.post("/license/nope/mercadopago/subscription-link", json={}).status_code == 404


def test_mercadopago_failure_is_502(client, monkeypatch):
    _new_client(client, "k-mp-502")

    async def boom(license_key, payer_email=None):
        raise mp.MercadoPagoError("caido")

    monkeypatch.setattr(mp, "create_subscription_approval_link", boom)
    assert client.post("/license/k-mp-502/mercadopago/subscription-link", json={}).status_code == 502


# --- doble cobro entre pasarelas ----------------------------------------

def test_active_mercadopago_blocks_a_second_link_of_either_gateway(client, monkeypatch):
    _new_client(client, "k-dbl1")
    db.set_mp_preapproval_id("k-dbl1", "PRE-ACTIVE")

    async def status(_id):
        return "authorized"

    monkeypatch.setattr(mp, "get_subscription_status", status)
    assert client.post("/license/k-dbl1/mercadopago/subscription-link", json={}).status_code == 409
    assert client.post("/license/k-dbl1/paypal/subscription-link", json={}).status_code == 409


def test_active_paypal_blocks_a_mercadopago_link(client, monkeypatch):
    _new_client(client, "k-dbl2")
    db.set_paypal_subscription_id("k-dbl2", "I-ACTIVE")

    async def status(_id):
        return "ACTIVE"

    monkeypatch.setattr(paypal, "get_subscription_status", status)
    assert client.post("/license/k-dbl2/mercadopago/subscription-link", json={}).status_code == 409


def test_cancelled_mercadopago_allows_a_new_link(client, monkeypatch):
    _new_client(client, "k-dbl3")
    db.set_mp_preapproval_id("k-dbl3", "PRE-OLD")

    async def status(_id):
        return "cancelled"

    async def fake_create(license_key, payer_email=None):
        return "PRE-NEW", "https://mp.test/new", 1000

    monkeypatch.setattr(mp, "get_subscription_status", status)
    monkeypatch.setattr(mp, "create_subscription_approval_link", fake_create)
    assert client.post("/license/k-dbl3/mercadopago/subscription-link", json={}).status_code == 200
    assert db.get_client("k-dbl3")["mp_preapproval_id"] == "PRE-NEW"


# --- webhook ------------------------------------------------------------

def test_processed_payment_extends_exactly_30_days(client, monkeypatch):
    _new_client(client, "k-w1", days=1)
    db.set_mp_preapproval_id("k-w1", "PRE-W1")
    _fake_payment(monkeypatch, {"AP1": _processed("PRE-W1")})
    before = _expiry("k-w1")
    assert _signed_post(client, "AP1").status_code == 204
    assert _expiry("k-w1") - before == timedelta(days=30)


def test_retried_notification_does_not_extend_twice(client, monkeypatch):
    _new_client(client, "k-w2", days=1)
    db.set_mp_preapproval_id("k-w2", "PRE-W2")
    _fake_payment(monkeypatch, {"AP2": _processed("PRE-W2")})
    _signed_post(client, "AP2")
    after_first = _expiry("k-w2")
    _signed_post(client, "AP2")
    _signed_post(client, "AP2")
    assert _expiry("k-w2") == after_first


def test_each_recurring_payment_adds_30_days(client, monkeypatch):
    _new_client(client, "k-w3", days=1)
    db.set_mp_preapproval_id("k-w3", "PRE-W3")
    _fake_payment(monkeypatch, {"AP3A": _processed("PRE-W3"), "AP3B": _processed("PRE-W3")})
    start = _expiry("k-w3")
    _signed_post(client, "AP3A")
    _signed_post(client, "AP3B")
    assert _expiry("k-w3") - start == timedelta(days=60)


@pytest.mark.parametrize(
    "payment",
    [
        {"status": "scheduled", "preapproval_id": "PRE-W4"},
        {"status": "recycling", "preapproval_id": "PRE-W4", "payment": {"status": "rejected"}},
        {"status": "cancelled", "preapproval_id": "PRE-W4"},
        {"status": "processed", "preapproval_id": "PRE-W4", "payment": {"status": "rejected"}},
    ],
)
def test_unpaid_states_do_not_extend(client, monkeypatch, payment):
    key = f"k-w4-{payment['status']}-{(payment.get('payment') or {}).get('status', '')}"
    _new_client(client, key, days=1)
    db.set_mp_preapproval_id(key, f"PRE-{key}")
    payment = {**payment, "preapproval_id": f"PRE-{key}"}
    _fake_payment(monkeypatch, {"AP4": payment})
    before = _expiry(key)
    assert _signed_post(client, "AP4").status_code == 204
    assert _expiry(key) == before


def test_unprocessed_then_processed_still_extends_once(client, monkeypatch):
    # Mercado Pago avisa varias veces por el mismo cobro (scheduled, luego processed).
    _new_client(client, "k-w5", days=1)
    db.set_mp_preapproval_id("k-w5", "PRE-W5")
    payments = {"AP5": {"status": "scheduled", "preapproval_id": "PRE-W5"}}
    _fake_payment(monkeypatch, payments)
    before = _expiry("k-w5")
    _signed_post(client, "AP5")
    assert _expiry("k-w5") == before
    payments["AP5"] = _processed("PRE-W5")
    _signed_post(client, "AP5")
    assert _expiry("k-w5") - before == timedelta(days=30)


def test_invalid_signature_is_rejected(client, monkeypatch):
    _new_client(client, "k-w6", days=1)
    db.set_mp_preapproval_id("k-w6", "PRE-W6")
    _fake_payment(monkeypatch, {"AP6": _processed("PRE-W6")})
    before = _expiry("k-w6")
    assert _signed_post(client, "AP6", secret="otra-clave").status_code == 401
    assert _expiry("k-w6") == before


def test_unsigned_notification_is_accepted_by_default_and_rechecked_with_the_api(client, monkeypatch):
    # Mercado Pago puede no firmar los avisos de Suscripciones: se acepta, pero el
    # estado del cobro sale de SU API (aca simulada), nunca del aviso.
    _new_client(client, "k-w7", days=1)
    db.set_mp_preapproval_id("k-w7", "PRE-W7")
    _fake_payment(monkeypatch, {"AP7": _processed("PRE-W7")})
    before = _expiry("k-w7")
    r = client.post("/webhooks/mercadopago?data.id=AP7&type=subscription_authorized_payment", json={})
    assert r.status_code == 204
    assert _expiry("k-w7") - before == timedelta(days=30)


def test_unsigned_notification_for_an_unpaid_charge_changes_nothing(client, monkeypatch):
    _new_client(client, "k-w7b", days=1)
    db.set_mp_preapproval_id("k-w7b", "PRE-W7B")
    _fake_payment(monkeypatch, {"AP7B": {"status": "scheduled", "preapproval_id": "PRE-W7B"}})
    before = _expiry("k-w7b")
    # Un atacante puede mandar el aviso, pero la API dice que no se pago.
    client.post("/webhooks/mercadopago?data.id=AP7B&type=subscription_authorized_payment", json={})
    assert _expiry("k-w7b") == before


def test_unsigned_notification_is_rejected_when_signature_is_required(client, monkeypatch):
    monkeypatch.setattr(mp, "MP_WEBHOOK_REQUIRE_SIGNATURE", True)
    r = client.post("/webhooks/mercadopago?data.id=AP7C&type=subscription_authorized_payment", json={})
    assert r.status_code == 401


def test_wrong_signature_is_rejected_even_when_signing_is_optional(client, monkeypatch):
    _new_client(client, "k-w7d", days=1)
    db.set_mp_preapproval_id("k-w7d", "PRE-W7D")
    _fake_payment(monkeypatch, {"AP7D": _processed("PRE-W7D")})
    r = client.post(
        "/webhooks/mercadopago?data.id=AP7D&type=subscription_authorized_payment",
        json={},
        headers={"x-signature": "ts=1,v1=deadbeef", "x-request-id": "r"},
    )
    assert r.status_code == 401


def test_unknown_customer_returns_409_and_can_be_retried(client, monkeypatch):
    _fake_payment(monkeypatch, {"AP8": _processed("PRE-NADIE")})

    async def no_pre(_id):
        return None

    monkeypatch.setattr(mp, "get_preapproval", no_pre)
    assert _signed_post(client, "AP8").status_code == 409
    # Despues queda vinculado: el reintento SI se acredita (el claim se solto).
    _new_client(client, "k-w8", days=1)
    db.set_mp_preapproval_id("k-w8", "PRE-NADIE")
    before = _expiry("k-w8")
    assert _signed_post(client, "AP8").status_code == 204
    assert _expiry("k-w8") - before == timedelta(days=30)


def test_customer_resolved_by_external_reference(client, monkeypatch):
    _new_client(client, "k-w9", days=1)
    _fake_payment(monkeypatch, {"AP9": _processed("PRE-W9")})

    async def pre(_id):
        return {"id": "PRE-W9", "external_reference": "k-w9", "status": "authorized"}

    monkeypatch.setattr(mp, "get_preapproval", pre)
    before = _expiry("k-w9")
    assert _signed_post(client, "AP9").status_code == 204
    assert _expiry("k-w9") - before == timedelta(days=30)
    assert db.get_client("k-w9")["mp_preapproval_id"] == "PRE-W9"


def test_api_error_while_checking_the_payment_is_retryable(client, monkeypatch):
    async def boom(_id):
        raise mp.MercadoPagoError("caido")

    monkeypatch.setattr(mp, "get_authorized_payment", boom)
    assert _signed_post(client, "AP10").status_code == 502


def test_preapproval_notification_links_but_never_extends(client, monkeypatch):
    _new_client(client, "k-w11", days=1)

    async def pre(_id):
        return {"id": "PRE-W11", "external_reference": "k-w11", "status": "authorized"}

    monkeypatch.setattr(mp, "get_preapproval", pre)
    before = _expiry("k-w11")
    assert _signed_post(client, "PRE-W11", event_type="subscription_preapproval").status_code == 204
    assert _expiry("k-w11") == before
    assert db.get_client("k-w11")["mp_preapproval_id"] == "PRE-W11"
    assert "Mercado Pago: suscripcion aprobada" in db.get_client("k-w11")["notes"]


def test_other_notification_types_are_ignored(client):
    assert _signed_post(client, "999", event_type="payment").status_code == 204


def test_webhook_503_when_not_configured(client, monkeypatch):
    monkeypatch.setattr(mp, "MP_ACCESS_TOKEN", "")
    assert _signed_post(client, "AP12").status_code == 503


# --- cancelar -----------------------------------------------------------

def test_cancel_cancels_mercadopago_and_keeps_expiry(client, monkeypatch):
    _new_client(client, "k-c1", days=10)
    db.set_mp_preapproval_id("k-c1", "PRE-C1")
    cancelled = []

    async def fake_cancel(pid):
        cancelled.append(pid)

    monkeypatch.setattr(mp, "cancel_subscription", fake_cancel)
    before = _expiry("k-c1")
    r = client.post("/license/k-c1/cancel-subscription")
    assert r.status_code == 200 and r.json()["cancelled"] is True
    assert cancelled == ["PRE-C1"]
    assert _expiry("k-c1") == before


def test_cancel_cancels_both_gateways_when_both_linked(client, monkeypatch):
    _new_client(client, "k-c2", days=10)
    db.set_mp_preapproval_id("k-c2", "PRE-C2")
    db.set_paypal_subscription_id("k-c2", "I-C2")
    calls = []

    async def mp_cancel(pid):
        calls.append(("mp", pid))

    async def pp_cancel(sid, reason="x"):
        calls.append(("pp", sid))

    monkeypatch.setattr(mp, "cancel_subscription", mp_cancel)
    monkeypatch.setattr(paypal, "cancel_subscription", pp_cancel)
    assert client.post("/license/k-c2/cancel-subscription").status_code == 200
    assert sorted(calls) == [("mp", "PRE-C2"), ("pp", "I-C2")]


def test_cancel_404_when_nothing_linked(client):
    _new_client(client, "k-c3")
    assert client.post("/license/k-c3/cancel-subscription").status_code == 404


# --- cotizacion y creacion contra la API (httpx simulado) ----------------

def _patch_http(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(mp.httpx, "AsyncClient", factory)


def test_price_ars_converts_usd_with_margin(monkeypatch):
    monkeypatch.setattr(mp, "MP_PRICE_USD", 250.0)
    monkeypatch.setattr(mp, "MP_FX_MARGIN_PCT", 0.0)
    assert mp.price_ars(1500.0) == 375000
    monkeypatch.setattr(mp, "MP_FX_MARGIN_PCT", 10.0)
    assert mp.price_ars(1500.0) == 412500


def test_creates_pending_ars_subscription_with_converted_amount(monkeypatch):
    monkeypatch.setattr(mp, "MP_ACCESS_TOKEN", "tok")
    monkeypatch.setattr(mp, "MP_NOTIFICATION_URL", "https://lic.test/webhooks/mercadopago")
    monkeypatch.setattr(mp, "_fx_cache", {"rate": None, "at": 0.0})
    seen = {}

    def handler(request: httpx.Request):
        if "dolarapi" in str(request.url):
            return httpx.Response(200, json={"venta": 1400.5, "compra": 1380})
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = __import__("json").loads(request.content)
        return httpx.Response(201, json={"id": "PRE-X", "init_point": "https://mp.test/go"})

    _patch_http(monkeypatch, handler)
    import asyncio

    pid, url, amount = asyncio.run(mp.create_subscription_approval_link("LK1", "a@b.com"))
    assert (pid, url) == ("PRE-X", "https://mp.test/go")
    assert amount == round(250 * 1400.5)
    body = seen["body"]
    assert seen["auth"] == "Bearer tok"
    assert body["external_reference"] == "LK1" and body["status"] == "pending"
    assert body["payer_email"] == "a@b.com"
    assert body["notification_url"] == "https://lic.test/webhooks/mercadopago"
    assert body["auto_recurring"] == {
        "frequency": 30, "frequency_type": "days", "transaction_amount": amount, "currency_id": "ARS",
    }


@pytest.mark.parametrize("bad", [{"venta": 1}, {"venta": 0}, {"venta": "x"}, {}, {"venta": 99999999}])
def test_garbage_rate_is_rejected_without_fallback(monkeypatch, bad):
    import asyncio

    monkeypatch.setattr(mp, "_fx_cache", {"rate": None, "at": 0.0})
    monkeypatch.setattr(mp, "MP_FALLBACK_RATE", "")
    _patch_http(monkeypatch, lambda r: httpx.Response(200, json=bad))
    with pytest.raises(mp.MercadoPagoError):
        asyncio.run(mp.get_usd_ars_rate())


def test_fx_api_down_uses_fallback_rate(monkeypatch):
    import asyncio

    monkeypatch.setattr(mp, "_fx_cache", {"rate": None, "at": 0.0})
    monkeypatch.setattr(mp, "MP_FALLBACK_RATE", "1300")
    _patch_http(monkeypatch, lambda r: httpx.Response(503))
    assert asyncio.run(mp.get_usd_ars_rate()) == 1300.0


def test_rate_is_cached(monkeypatch):
    import asyncio

    monkeypatch.setattr(mp, "_fx_cache", {"rate": None, "at": 0.0})
    hits = []

    def handler(request):
        hits.append(1)
        return httpx.Response(200, json={"venta": 1500})

    _patch_http(monkeypatch, handler)
    asyncio.run(mp.get_usd_ars_rate())
    asyncio.run(mp.get_usd_ars_rate())
    assert len(hits) == 1
