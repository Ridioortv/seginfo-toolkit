"""Tests del flujo de cobro por PayPal del servidor de licencias (sin tocar la
red: paypal.py se reemplaza por dobles). Correr desde licensing-server/:
    python -m pytest -q tests"""
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="lic-test-")
os.environ["ADMIN_TOKEN"] = "test-admin-token"
os.environ["LICENSING_DB_PATH"] = os.path.join(_tmp, "t.db")
os.environ.pop("DATABASE_URL", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import db, main, paypal  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}


@pytest.fixture()
def client(monkeypatch):
    with TestClient(main.app) as c:
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_ID", "id")
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_SECRET", "secret")

        async def _verified(headers, body):
            return True

        monkeypatch.setattr(paypal, "verify_webhook_signature", _verified)
        yield c


def _new_client(c, key, days=1):
    r = c.post("/admin/clients", headers=ADMIN, json={"org_name": "ACME", "license_key": key, "days": days})
    assert r.status_code == 201
    return r.json()


def _expiry(key):
    return datetime.fromisoformat(db.get_client(key)["subscription_expires_at"])


def _sale(event_id, sub_id):
    return {"id": event_id, "event_type": "PAYMENT.SALE.COMPLETED", "resource": {"billing_agreement_id": sub_id}}


def test_public_link_creates_subscription_and_links_it(client, monkeypatch):
    _new_client(client, "k-link")
    seen = {}

    async def fake_create(license_key, plan_id=None, payer_email=None):
        seen.update(license_key=license_key, payer_email=payer_email)
        return "I-SUB1", "https://paypal.test/approve"

    monkeypatch.setattr(paypal, "create_subscription_approval_link", fake_create)
    r = client.post("/license/k-link/paypal/subscription-link", json={"payer_email": "a@b.com"})
    assert r.status_code == 200
    assert r.json() == {"subscription_id": "I-SUB1", "approval_url": "https://paypal.test/approve"}
    assert seen == {"license_key": "k-link", "payer_email": "a@b.com"}
    assert db.get_client("k-link")["paypal_subscription_id"] == "I-SUB1"


def test_public_link_503_when_paypal_not_configured(client, monkeypatch):
    _new_client(client, "k-503")
    monkeypatch.setattr(paypal, "PAYPAL_CLIENT_ID", "")
    assert client.post("/license/k-503/paypal/subscription-link", json={}).status_code == 503


def test_public_link_404_unknown_license(client):
    assert client.post("/license/nope/paypal/subscription-link", json={}).status_code == 404


def test_first_payment_extends_exactly_30_days_not_60(client):
    # ACTIVATED + PAYMENT.SALE.COMPLETED llegan juntos en el primer cobro:
    # solo el segundo debe sumar dias.
    _new_client(client, "k-first", days=1)
    db.set_paypal_subscription_id("k-first", "I-SUB2")
    before = _expiry("k-first")
    activated = {"id": "WH-1", "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
                 "resource": {"id": "I-SUB2", "custom_id": "k-first"}}
    assert client.post("/webhooks/paypal", json=activated).status_code == 204
    assert _expiry("k-first") == before  # activar no extiende
    assert client.post("/webhooks/paypal", json=_sale("WH-2", "I-SUB2")).status_code == 204
    assert _expiry("k-first") - before == timedelta(days=30)


def test_retried_webhook_does_not_extend_twice(client):
    _new_client(client, "k-dup", days=1)
    db.set_paypal_subscription_id("k-dup", "I-SUB3")
    ev = _sale("WH-DUP", "I-SUB3")
    client.post("/webhooks/paypal", json=ev)
    after_first = _expiry("k-dup")
    client.post("/webhooks/paypal", json=ev)
    client.post("/webhooks/paypal", json=ev)
    assert _expiry("k-dup") == after_first


def test_recurring_payments_each_add_30_days(client):
    _new_client(client, "k-rec", days=1)
    db.set_paypal_subscription_id("k-rec", "I-SUB4")
    start = _expiry("k-rec")
    client.post("/webhooks/paypal", json=_sale("WH-A", "I-SUB4"))
    client.post("/webhooks/paypal", json=_sale("WH-B", "I-SUB4"))
    assert _expiry("k-rec") - start == timedelta(days=60)


def test_invalid_signature_is_rejected(client, monkeypatch):
    _new_client(client, "k-sig", days=1)
    db.set_paypal_subscription_id("k-sig", "I-SUB5")

    async def _bad(headers, body):
        return False

    monkeypatch.setattr(paypal, "verify_webhook_signature", _bad)
    before = _expiry("k-sig")
    assert client.post("/webhooks/paypal", json=_sale("WH-X", "I-SUB5")).status_code == 401
    assert _expiry("k-sig") == before


def test_cancel_keeps_paid_period(client, monkeypatch):
    _new_client(client, "k-can", days=10)
    db.set_paypal_subscription_id("k-can", "I-SUB6")
    called = {}

    async def fake_cancel(sub_id, reason="x"):
        called["id"] = sub_id

    monkeypatch.setattr(paypal, "cancel_subscription", fake_cancel)
    before = _expiry("k-can")
    r = client.post("/license/k-can/paypal/cancel-subscription")
    assert r.status_code == 200 and r.json()["cancelled"] is True
    assert called["id"] == "I-SUB6"
    assert _expiry("k-can") == before


def test_cancel_404_without_linked_subscription(client):
    _new_client(client, "k-nosub")
    assert client.post("/license/k-nosub/paypal/cancel-subscription").status_code == 404


def test_billing_alias_route_works_like_paypal_route(client):
    _new_client(client, "k-alias", days=1)
    db.set_paypal_subscription_id("k-alias", "I-SUB7")
    before = _expiry("k-alias")
    assert client.post("/webhooks/billing", json=_sale("WH-AL", "I-SUB7")).status_code == 204
    assert _expiry("k-alias") - before == timedelta(days=30)


def test_second_link_refused_while_subscription_is_active(client, monkeypatch):
    """Evita el doble cobro: con una suscripcion ACTIVA no se crea otra."""
    _new_client(client, "k-dobleclick")
    created = []

    async def fake_create(license_key, plan_id=None, payer_email=None):
        created.append(1)
        return f"I-DOBLECLICK-{len(created)}", "https://paypal.test/approve"

    async def fake_status(sub_id):
        return "ACTIVE"

    monkeypatch.setattr(paypal, "create_subscription_approval_link", fake_create)
    monkeypatch.setattr(paypal, "get_subscription_status", fake_status)

    assert client.post("/license/k-dobleclick/paypal/subscription-link", json={"payer_email": "a@b.com"}).status_code == 200
    r = client.post("/license/k-dobleclick/paypal/subscription-link", json={"payer_email": "a@b.com"})
    assert r.status_code == 409 and "activa" in r.json()["detail"]
    r = client.post("/admin/clients/k-dobleclick/paypal-subscription-link", headers=ADMIN, json={})
    assert r.status_code == 409
    assert len(created) == 1  # nunca se creo una segunda suscripcion en PayPal


def test_new_link_allowed_when_previous_not_active(client, monkeypatch):
    """Si la anterior se cancelo/vencio o nunca se aprobo, se puede crear otra."""
    _new_client(client, "k-redo")
    states = iter(["APPROVAL_PENDING", "CANCELLED", None])

    async def fake_create(license_key, plan_id=None, payer_email=None):
        return "I-SUBX", "https://paypal.test/approve"

    async def fake_status(sub_id):
        return next(states)

    monkeypatch.setattr(paypal, "create_subscription_approval_link", fake_create)
    monkeypatch.setattr(paypal, "get_subscription_status", fake_status)
    for _ in range(4):  # la 1ra no tiene suscripcion previa; las otras 3 consultan estados no bloqueantes
        r = client.post("/license/k-redo/paypal/subscription-link", json={"payer_email": "a@b.com"})
        assert r.status_code == 200


def test_sale_before_link_is_retried_not_dropped(client):
    """PAYMENT.SALE.COMPLETED puede llegar antes de que ACTIVATED relinke la
    suscripcion: no se descarta, PayPal lo reintenta (409) y al reintentar se acredita."""
    _new_client(client, "k-late", days=1)
    db.set_paypal_subscription_id("k-late", "I-NEW")
    before = _expiry("k-late")
    sale = _sale("WH-LATE", "I-OLD")
    assert client.post("/webhooks/paypal", json=sale).status_code == 409  # PayPal reintenta
    assert _expiry("k-late") == before
    activated = {"id": "WH-LATE-A", "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
                 "resource": {"id": "I-OLD", "custom_id": "k-late"}}
    assert client.post("/webhooks/paypal", json=activated).status_code == 204
    assert client.post("/webhooks/paypal", json=sale).status_code == 204  # reintento del MISMO evento
    assert _expiry("k-late") - before == timedelta(days=30)
    assert client.post("/webhooks/paypal", json=sale).status_code == 204  # y no se duplica
    assert _expiry("k-late") - before == timedelta(days=30)


def test_transient_error_does_not_burn_the_event(client, monkeypatch):
    _new_client(client, "k-err", days=1)
    db.set_paypal_subscription_id("k-err", "I-ERR")
    before = _expiry("k-err")
    real = db.get_client_by_paypal_subscription_id
    calls = {"n": 0}

    def flaky(value):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db caida")
        return real(value)

    monkeypatch.setattr(db, "get_client_by_paypal_subscription_id", flaky)
    sale = _sale("WH-ERR", "I-ERR")
    try:
        r = client.post("/webhooks/paypal", json=sale)
        assert r.status_code >= 500
    except RuntimeError:
        pass  # TestClient re-lanza la excepcion del servidor
    assert _expiry("k-err") == before
    assert client.post("/webhooks/paypal", json=sale).status_code == 204
    assert _expiry("k-err") - before == timedelta(days=30)
