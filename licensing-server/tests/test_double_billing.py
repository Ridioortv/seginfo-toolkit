"""Doble cobro: una licencia nunca debe quedar con dos suscripciones cobrando.

1. Un link nuevo cancela los links anteriores que nadie aprobo.
2. Si se aprueban dos suscripciones, la segunda se cancela sola y la licencia se
   extiende una sola vez.
3. "Cancelar suscripcion" cancela TODAS las vivas, no solo la ultima.
Sin tocar la red: las llamadas a las pasarelas se reemplazan por dobles."""
import hashlib
import hmac
import os
import tempfile
from datetime import datetime, timedelta

import pytest

_tmp = tempfile.mkdtemp(prefix="lic-dbl-test-")
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
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_ID", "id")
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_SECRET", "secret")
        yield c


class Gateways:
    """Dobles de las dos pasarelas: estado de cada suscripcion + registro de
    las cancelaciones que se pidieron."""

    def __init__(self, monkeypatch):
        self.mp_status: dict[str, str] = {}
        self.pp_status: dict[str, str] = {}
        self.cancelled: list[tuple[str, str]] = []
        self.created = 0
        self.fail_status: set[str] = set()
        self.fail_cancel: set[str] = set()

        async def mp_get_status(pid):
            if pid in self.fail_status:
                raise mp.MercadoPagoError("caido")
            return self.mp_status.get(pid)

        async def pp_get_status(sid):
            if sid in self.fail_status:
                raise paypal.PayPalError("caido")
            return self.pp_status.get(sid)

        async def mp_cancel(pid):
            if pid in self.fail_cancel:
                raise mp.MercadoPagoError("no se pudo cancelar")
            self.cancelled.append(("mp", pid))
            self.mp_status[pid] = "cancelled"

        async def pp_cancel(sid, reason="x"):
            self.cancelled.append(("pp", sid))
            self.pp_status[sid] = "CANCELLED"

        async def mp_create(license_key, payer_email=None):
            self.created += 1
            pid = f"PRE-{license_key}-{self.created}"
            self.mp_status[pid] = "pending"
            return pid, f"https://mp.test/{pid}", 1000

        async def pp_create(license_key, plan_id=None, payer_email=None):
            self.created += 1
            sid = f"I-{license_key}-{self.created}"
            self.pp_status[sid] = "APPROVAL_PENDING"
            return sid, f"https://pp.test/{sid}"

        monkeypatch.setattr(mp, "get_subscription_status", mp_get_status)
        monkeypatch.setattr(paypal, "get_subscription_status", pp_get_status)
        monkeypatch.setattr(mp, "cancel_subscription", mp_cancel)
        monkeypatch.setattr(paypal, "cancel_subscription", pp_cancel)
        monkeypatch.setattr(mp, "create_subscription_approval_link", mp_create)
        monkeypatch.setattr(paypal, "create_subscription_approval_link", pp_create)

        async def get_preapproval(pid):
            sub = db.get_subscription("mercadopago", pid)
            if sub is None:
                return None
            return {"id": pid, "external_reference": sub["license_key"], "status": self.mp_status.get(pid, "")}

        monkeypatch.setattr(mp, "get_preapproval", get_preapproval)
        self.payments: dict[str, dict] = {}

        async def get_payment(ap_id):
            return self.payments.get(ap_id)

        monkeypatch.setattr(mp, "get_authorized_payment", get_payment)

    def pay_mp(self, ap_id, preapproval_id):
        self.payments[ap_id] = {"status": "processed", "preapproval_id": preapproval_id, "payment": {"status": "approved"}}


@pytest.fixture()
def gw(monkeypatch):
    return Gateways(monkeypatch)


def _new_client(c, key, days=1):
    assert c.post("/admin/clients", headers=ADMIN, json={"org_name": "ACME", "license_key": key, "days": days}).status_code == 201


def _expiry(key):
    return datetime.fromisoformat(db.get_client(key)["subscription_expires_at"])


def _mp_notify(c, data_id, event_type):
    ts, rid = "1700000000", "req-1"
    sid = data_id.lower() if data_id.isalnum() else data_id
    manifest = f"id:{sid};request-id:{rid};ts:{ts};"
    v1 = hmac.new(SECRET.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    return c.post(
        f"/webhooks/mercadopago?data.id={data_id}&type={event_type}",
        json={"type": event_type, "data": {"id": data_id}},
        headers={"x-signature": f"ts={ts},v1={v1}", "x-request-id": rid},
    )


def _statuses(key):
    return {(s["gateway"], s["external_id"]): s["status"] for s in db.list_subscriptions(key)}


# --- 1. un link nuevo cancela los anteriores sin pagar ------------------------

def test_second_mercadopago_link_cancels_the_first_one(client, gw):
    _new_client(client, "k-d1")
    first = client.post("/license/k-d1/mercadopago/subscription-link", json={}).json()["subscription_id"]
    second = client.post("/license/k-d1/mercadopago/subscription-link", json={}).json()["subscription_id"]
    assert first != second
    assert gw.cancelled == [("mp", first)]
    assert _statuses("k-d1") == {("mercadopago", first): "cancelled", ("mercadopago", second): "pending"}
    assert "link de pago anterior" in db.get_client("k-d1")["notes"]


def test_a_link_of_the_other_gateway_also_cancels_the_pending_one(client, gw):
    _new_client(client, "k-d2")
    mp_id = client.post("/license/k-d2/mercadopago/subscription-link", json={}).json()["subscription_id"]
    pp_id = client.post("/license/k-d2/paypal/subscription-link", json={}).json()["subscription_id"]
    assert gw.cancelled == [("mp", mp_id)]
    assert _statuses("k-d2")[("paypal", pp_id)] == "pending"


def test_three_paypal_links_leave_only_the_last_one_pending(client, gw):
    _new_client(client, "k-d3")
    ids = [client.post("/license/k-d3/paypal/subscription-link", json={}).json()["subscription_id"] for _ in range(3)]
    assert gw.cancelled == [("pp", ids[0]), ("pp", ids[1])]
    assert [s for s, st in _statuses("k-d3").items() if st == "pending"] == [("paypal", ids[2])]


def test_failure_cancelling_the_old_link_does_not_block_the_new_one(client, gw):
    _new_client(client, "k-d4")
    first = client.post("/license/k-d4/mercadopago/subscription-link", json={}).json()["subscription_id"]
    gw.fail_cancel.add(first)
    r = client.post("/license/k-d4/mercadopago/subscription-link", json={})
    assert r.status_code == 200
    assert "no se pudo cancelar el link de pago anterior" in db.get_client("k-d4")["notes"]
    assert _statuses("k-d4")[("mercadopago", first)] == "pending"  # sigue figurando: se reintenta en el proximo link


# --- 2. dos suscripciones aprobadas: la segunda se cancela y no extiende --------

def test_second_approved_mercadopago_subscription_is_cancelled_and_extends_nothing(client, gw):
    _new_client(client, "k-d5", days=1)
    # Dos links que quedaron pagables (p. ej. generados por versiones anteriores).
    db.set_mp_preapproval_id("k-d5", "PRE-A")
    db.set_mp_preapproval_id("k-d5", "PRE-B")
    gw.mp_status.update({"PRE-A": "authorized", "PRE-B": "authorized"})
    before = _expiry("k-d5")

    assert _mp_notify(client, "PRE-A", "subscription_preapproval").status_code == 204
    gw.pay_mp("DBL-AP-A", "PRE-A")
    assert _mp_notify(client, "DBL-AP-A", "subscription_authorized_payment").status_code == 204
    assert _expiry("k-d5") - before == timedelta(days=30)

    # Se aprueba y cobra la segunda.
    assert _mp_notify(client, "PRE-B", "subscription_preapproval").status_code == 204
    gw.pay_mp("DBL-AP-B", "PRE-B")
    assert _mp_notify(client, "DBL-AP-B", "subscription_authorized_payment").status_code == 204

    assert ("mp", "PRE-B") in gw.cancelled and ("mp", "PRE-A") not in gw.cancelled
    assert _statuses("k-d5") == {("mercadopago", "PRE-A"): "active", ("mercadopago", "PRE-B"): "duplicate"}
    assert _expiry("k-d5") - before == timedelta(days=30)  # una sola extension
    notes = db.get_client("k-d5")["notes"]
    assert "devolver ese pago" in notes and "PRE-B" in notes


def test_payment_of_the_duplicate_arriving_before_its_approval_is_not_credited(client, gw):
    _new_client(client, "k-d6", days=1)
    db.set_mp_preapproval_id("k-d6", "PRE-A6")
    db.set_mp_preapproval_id("k-d6", "PRE-B6")
    gw.mp_status.update({"PRE-A6": "authorized", "PRE-B6": "authorized"})
    before = _expiry("k-d6")
    gw.pay_mp("DBL-AP-A6", "PRE-A6")
    gw.pay_mp("DBL-AP-B6", "PRE-B6")
    assert _mp_notify(client, "DBL-AP-A6", "subscription_authorized_payment").status_code == 204
    assert _mp_notify(client, "DBL-AP-B6", "subscription_authorized_payment").status_code == 204
    assert _expiry("k-d6") - before == timedelta(days=30)
    assert gw.cancelled == [("mp", "PRE-B6")]


def test_recurring_payments_of_the_active_subscription_keep_extending(client, gw):
    _new_client(client, "k-d7", days=1)
    db.set_mp_preapproval_id("k-d7", "PRE-A7")
    gw.mp_status["PRE-A7"] = "authorized"
    before = _expiry("k-d7")
    for n in (1, 2, 3):
        gw.pay_mp(f"DBL-AP7-{n}", "PRE-A7")
        assert _mp_notify(client, f"DBL-AP7-{n}", "subscription_authorized_payment").status_code == 204
    assert _expiry("k-d7") - before == timedelta(days=90)
    assert gw.cancelled == []


def test_paypal_second_approval_is_cancelled_and_its_sale_extends_nothing(client, gw, monkeypatch):
    async def ok_verify(headers, body):
        return True

    monkeypatch.setattr(paypal, "verify_webhook_signature", ok_verify)
    _new_client(client, "k-d8", days=1)
    db.set_paypal_subscription_id("k-d8", "I-A8")
    db.set_paypal_subscription_id("k-d8", "I-B8")
    gw.pp_status.update({"I-A8": "ACTIVE", "I-B8": "ACTIVE"})
    before = _expiry("k-d8")

    def activated(event_id, sub_id):
        return {"id": event_id, "event_type": "BILLING.SUBSCRIPTION.ACTIVATED", "resource": {"id": sub_id, "custom_id": "k-d8"}}

    def sale(event_id, sub_id):
        return {"id": event_id, "event_type": "PAYMENT.SALE.COMPLETED", "resource": {"billing_agreement_id": sub_id}}

    for event in (activated("W1", "I-A8"), sale("W2", "I-A8"), activated("W3", "I-B8"), sale("W4", "I-B8")):
        assert client.post("/webhooks/paypal", json=event).status_code == 204
    assert gw.cancelled == [("pp", "I-B8")]
    assert _statuses("k-d8") == {("paypal", "I-A8"): "active", ("paypal", "I-B8"): "duplicate"}
    assert _expiry("k-d8") - before == timedelta(days=30)


def test_a_cobro_from_an_older_link_is_not_lost(client, gw):
    """El cobro llega de un link que NO es el ultimo que se genero: se acredita igual."""
    _new_client(client, "k-d9", days=1)
    db.set_mp_preapproval_id("k-d9", "PRE-OLD9")
    db.set_mp_preapproval_id("k-d9", "PRE-NEW9")  # la columna de `clients` ahora apunta a este
    before = _expiry("k-d9")
    gw.pay_mp("DBL-AP9", "PRE-OLD9")
    assert _mp_notify(client, "DBL-AP9", "subscription_authorized_payment").status_code == 204
    assert _expiry("k-d9") - before == timedelta(days=30)


def test_the_other_subscription_was_cancelled_by_the_customer_so_the_new_one_is_not_a_duplicate(client, gw):
    _new_client(client, "k-d10", days=1)
    db.set_mp_preapproval_id("k-d10", "PRE-A10")
    gw.mp_status["PRE-A10"] = "authorized"
    gw.pay_mp("DBL-AP10A", "PRE-A10")
    _mp_notify(client, "DBL-AP10A", "subscription_authorized_payment")
    # El cliente cancela A por su cuenta (desde Mercado Pago) y paga un link nuevo.
    gw.mp_status["PRE-A10"] = "cancelled"
    db.set_mp_preapproval_id("k-d10", "PRE-B10")
    gw.mp_status["PRE-B10"] = "authorized"
    gw.pay_mp("DBL-AP10B", "PRE-B10")
    before = _expiry("k-d10")
    assert _mp_notify(client, "DBL-AP10B", "subscription_authorized_payment").status_code == 204
    assert _expiry("k-d10") - before == timedelta(days=30)
    assert _statuses("k-d10") == {("mercadopago", "PRE-A10"): "cancelled", ("mercadopago", "PRE-B10"): "active"}
    assert gw.cancelled == []


def test_if_the_other_subscription_cannot_be_verified_the_notice_is_retried(client, gw):
    _new_client(client, "k-d11", days=1)
    db.set_mp_preapproval_id("k-d11", "PRE-A11")
    db.set_mp_preapproval_id("k-d11", "PRE-B11")
    gw.mp_status.update({"PRE-A11": "authorized", "PRE-B11": "authorized"})
    gw.pay_mp("DBL-AP11A", "PRE-A11")
    _mp_notify(client, "DBL-AP11A", "subscription_authorized_payment")
    gw.fail_status.add("PRE-A11")
    gw.pay_mp("DBL-AP11B", "PRE-B11")
    before = _expiry("k-d11")
    assert _mp_notify(client, "DBL-AP11B", "subscription_authorized_payment").status_code == 502
    assert _expiry("k-d11") == before and gw.cancelled == []
    # Vuelve la pasarela: el reintento ahora si lo resuelve (duplicada, sin extender).
    gw.fail_status.clear()
    assert _mp_notify(client, "DBL-AP11B", "subscription_authorized_payment").status_code == 204
    assert _expiry("k-d11") == before and gw.cancelled == [("mp", "PRE-B11")]


# --- 3. cancelar cancela todas las vivas -------------------------------------

def test_cancel_cancels_every_live_subscription_of_the_license(client, gw):
    _new_client(client, "k-d12", days=10)
    db.set_mp_preapproval_id("k-d12", "PRE-1")
    db.set_mp_preapproval_id("k-d12", "PRE-2")
    db.set_paypal_subscription_id("k-d12", "I-1")
    assert db.claim_active_subscription("k-d12", "mercadopago", "PRE-1")
    before = _expiry("k-d12")
    r = client.post("/license/k-d12/cancel-subscription")
    assert r.status_code == 200 and r.json()["cancelled"] is True
    assert sorted(gw.cancelled) == [("mp", "PRE-1"), ("mp", "PRE-2"), ("pp", "I-1")]
    assert db.list_subscriptions("k-d12", statuses=("pending", "active")) == []
    assert _expiry("k-d12") == before  # el periodo pagado se respeta
    # Repetir es inofensivo.
    assert client.post("/license/k-d12/cancel-subscription").status_code == 200


def test_paypal_only_cancel_leaves_mercadopago_alone(client, gw):
    _new_client(client, "k-d13", days=10)
    db.set_paypal_subscription_id("k-d13", "I-13A")
    db.set_paypal_subscription_id("k-d13", "I-13B")
    db.set_mp_preapproval_id("k-d13", "PRE-13")
    assert client.post("/license/k-d13/paypal/cancel-subscription").status_code == 200
    assert sorted(gw.cancelled) == [("pp", "I-13A"), ("pp", "I-13B")]
    assert _statuses("k-d13")[("mercadopago", "PRE-13")] == "pending"


# --- base de datos -----------------------------------------------------------

def test_old_databases_get_their_existing_subscriptions_registered(client):
    _new_client(client, "k-d14")
    with db.get_cursor() as cur:
        cur.execute(
            db._adapt("UPDATE clients SET paypal_subscription_id = ?, mp_preapproval_id = ? WHERE license_key = ?"),
            ("I-LEGACY", "PRE-LEGACY", "k-d14"),
        )
    assert db.list_subscriptions("k-d14") == []
    db.init_db()
    db.init_db()  # idempotente
    assert _statuses("k-d14") == {("paypal", "I-LEGACY"): "pending", ("mercadopago", "PRE-LEGACY"): "pending"}


def test_only_one_subscription_can_claim_the_active_slot(client):
    _new_client(client, "k-d15")
    db.set_mp_preapproval_id("k-d15", "PRE-X")
    db.set_mp_preapproval_id("k-d15", "PRE-Y")
    assert db.claim_active_subscription("k-d15", "mercadopago", "PRE-X") is True
    assert db.claim_active_subscription("k-d15", "mercadopago", "PRE-Y") is False
    assert db.claim_active_subscription("k-d15", "mercadopago", "PRE-X") is True  # idempotente
