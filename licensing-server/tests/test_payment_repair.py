"""Regresion de las dos fallas reales al generar el link de pago (sin tocar la
red: PayPal y Mercado Pago se simulan con httpx.MockTransport).

1. PayPal 404 INVALID_RESOURCE_ID: el PAYPAL_PLAN_ID no existe en el entorno
   (sandbox/live) de las credenciales. Debe (a) explicar la causa y la solucion y
   (b) en sandbox -- o con PAYPAL_AUTO_CREATE_PLAN=1 -- crear el plan solo, una
   unica vez, y reutilizarlo.
2. Mercado Pago "cobrador y pagador tienen que ser los dos de prueba o los dos
   reales": con credenciales de prueba y el email real del cliente. Debe reintentar
   sin pagador (el comprador inicia sesion en el checkout) en vez de bloquear el pago.

Correr desde licensing-server/:  python -m pytest -q tests/test_payment_repair.py"""
import asyncio
import json
import os
import tempfile

import httpx
import pytest

_tmp = tempfile.mkdtemp(prefix="lic-repair-test-")
os.environ["ADMIN_TOKEN"] = "test-admin-token"
os.environ["LICENSING_DB_PATH"] = os.path.join(_tmp, "t.db")
os.environ.pop("DATABASE_URL", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import db, main, mercadopago as mp, paypal  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}

PLAN_404 = {
    "name": "RESOURCE_NOT_FOUND",
    "message": "The specified resource does not exist.",
    "details": [{"issue": "INVALID_RESOURCE_ID", "description": "Requested resource ID was not found."}],
}
MP_REAL_OR_TEST = {"message": "Both payer and collector must be real or test users", "error": "bad_request", "status": 400, "cause": []}


def _patch_http(monkeypatch, module, handler):
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)


# ------------------------------------------------------------------ PayPal
class FakePayPal:
    """PayPal minimo: solo conoce los planes que se le hayan creado (mas los
    `known` del arranque). Cuenta cuantas veces se creo cada cosa."""

    def __init__(self, known=(), sub_id="I-SUB"):
        self.sub_id = sub_id
        self.plans = set(known)
        self.products = 0
        self.plan_bodies = []
        self.subscription_plans = []
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "tok"})
        if path == "/v1/catalogs/products":
            self.products += 1
            return httpx.Response(201, json={"id": f"PROD-{self.products}"})
        if path == "/v1/billing/plans":
            body = json.loads(request.content)
            self.plan_bodies.append(body)
            plan_id = f"P-NEW{len(self.plan_bodies)}"
            self.plans.add(plan_id)
            return httpx.Response(201, json={"id": plan_id, "status": "ACTIVE"})
        if path == "/v1/billing/subscriptions":
            body = json.loads(request.content)
            self.subscription_plans.append(body["plan_id"])
            if body["plan_id"] not in self.plans:
                return httpx.Response(404, json=PLAN_404)
            return httpx.Response(201, json={
                "id": self.sub_id, "links": [{"rel": "approve", "href": "https://paypal.test/approve"}],
            })
        return httpx.Response(500)


@pytest.fixture()
def pp(monkeypatch):
    db.init_db()
    with db.get_cursor() as cur:
        cur.execute("DELETE FROM app_settings")
    monkeypatch.setattr(paypal, "PAYPAL_CLIENT_ID", "cid")
    monkeypatch.setattr(paypal, "PAYPAL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(paypal, "PAYPAL_ENV", "sandbox")
    monkeypatch.setattr(paypal, "PAYPAL_PLAN_ID", "P-OLD")
    monkeypatch.setattr(paypal, "PAYPAL_AUTO_CREATE_PLAN", "")
    monkeypatch.setattr(paypal, "_known_missing_plans", set())
    return monkeypatch


def _create(plan_id=None):
    return asyncio.run(paypal.create_subscription_approval_link("LK1", plan_id))


def test_missing_plan_in_live_explains_cause_and_does_not_create_anything(pp):
    pp.setattr(paypal, "PAYPAL_ENV", "live")
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    with pytest.raises(paypal.PayPalError) as exc:
        _create()
    msg = str(exc.value)
    assert "P-OLD" in msg and "live" in msg
    assert "PAYPAL_PLAN_ID" in msg and "create_paypal_plan.py" in msg and "PAYPAL_AUTO_CREATE_PLAN" in msg
    assert "INVALID_RESOURCE_ID" not in msg  # nada de volcar el JSON crudo de PayPal
    assert fake.products == 0 and fake.plan_bodies == []


def test_missing_plan_in_sandbox_creates_the_plan_and_the_link_works(pp):
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    sub_id, url = _create()
    assert (sub_id, url) == ("I-SUB", "https://paypal.test/approve")
    assert fake.subscription_plans == ["P-OLD", "P-NEW1"]  # primero el configurado, luego el creado
    assert fake.products == 1 and len(fake.plan_bodies) == 1


def test_auto_created_plan_is_usd_250_every_30_days_autorenewing(pp):
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    _create()
    cycle = fake.plan_bodies[0]["billing_cycles"][0]
    assert cycle["frequency"] == {"interval_unit": "DAY", "interval_count": 30}
    assert cycle["pricing_scheme"]["fixed_price"] == {"value": "250", "currency_code": "USD"}
    assert cycle["tenure_type"] == "REGULAR" and cycle["total_cycles"] == 0
    assert fake.plan_bodies[0]["product_id"] == "PROD-1"


def test_auto_created_plan_is_reused_and_never_duplicated(pp):
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    _create()
    _create()
    _create()
    assert fake.products == 1 and len(fake.plan_bodies) == 1
    # a partir de la segunda vez ni siquiera se vuelve a probar el plan roto
    assert fake.subscription_plans == ["P-OLD", "P-NEW1", "P-NEW1", "P-NEW1"]


def test_auto_created_plan_survives_a_restart(pp):
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    _create()
    pp.setattr(paypal, "_known_missing_plans", set())  # = proceso nuevo, la base sigue
    _create()
    assert fake.products == 1 and len(fake.plan_bodies) == 1


def test_stored_plan_deleted_in_paypal_is_replaced_once(pp):
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    _create()
    fake.plans.discard("P-NEW1")  # alguien lo borro en el dashboard
    pp.setattr(paypal, "_known_missing_plans", set())
    assert _create()[0] == "I-SUB"
    assert len(fake.plan_bodies) == 2


def test_two_simultaneous_links_create_only_one_plan(pp):
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)

    async def both():
        return await asyncio.gather(
            paypal.create_subscription_approval_link("LK1"), paypal.create_subscription_approval_link("LK2")
        )

    results = asyncio.run(both())
    assert [r[0] for r in results] == ["I-SUB", "I-SUB"]
    assert len(fake.plan_bodies) == 1


def test_live_with_explicit_opt_in_creates_the_plan(pp):
    pp.setattr(paypal, "PAYPAL_ENV", "live")
    pp.setattr(paypal, "PAYPAL_AUTO_CREATE_PLAN", "1")
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    assert _create()[0] == "I-SUB"
    assert len(fake.plan_bodies) == 1


def test_sandbox_can_opt_out_of_auto_creation(pp):
    pp.setattr(paypal, "PAYPAL_AUTO_CREATE_PLAN", "0")
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    with pytest.raises(paypal.PayPalError, match="P-OLD"):
        _create()
    assert fake.plan_bodies == []


def test_explicit_plan_from_the_admin_is_never_replaced(pp):
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    with pytest.raises(paypal.PayPalError, match="P-ADMIN"):
        _create("P-ADMIN")
    assert fake.plan_bodies == []


def test_no_plan_configured_at_all_in_sandbox_creates_one(pp):
    pp.setattr(paypal, "PAYPAL_PLAN_ID", "")
    fake = FakePayPal()
    _patch_http(pp, paypal, fake)
    assert _create()[0] == "I-SUB"
    assert fake.subscription_plans == ["P-NEW1"]


def test_no_plan_configured_in_live_keeps_the_clear_error(pp):
    pp.setattr(paypal, "PAYPAL_ENV", "live")
    pp.setattr(paypal, "PAYPAL_PLAN_ID", "")
    with pytest.raises(paypal.PayPalError, match="PAYPAL_PLAN_ID"):
        _create()


def test_other_404_is_not_mistaken_for_a_missing_plan(pp):
    def handler(request):
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(404, json={"name": "RESOURCE_NOT_FOUND", "details": [{"issue": "SOMETHING_ELSE"}]})

    _patch_http(pp, paypal, handler)
    with pytest.raises(paypal.PayPalError, match="rechazo la creacion de la suscripcion"):
        _create()


def test_plan_creation_failure_is_a_clear_error_not_a_crash(pp):
    def handler(request):
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "t"})
        if request.url.path == "/v1/billing/subscriptions":
            return httpx.Response(404, json=PLAN_404)
        return httpx.Response(403, json={"name": "NOT_AUTHORIZED"})

    _patch_http(pp, paypal, handler)
    with pytest.raises(paypal.PayPalError, match="crear el plan"):
        _create()


def test_endpoint_returns_200_with_the_link_when_the_plan_was_missing(pp):
    fake = FakePayPal(sub_id="I-REPAIR-EP1")
    _patch_http(pp, paypal, fake)
    with TestClient(main.app) as c:
        assert c.post("/admin/clients", headers=ADMIN, json={"org_name": "A", "license_key": "k-pp-fix"}).status_code == 201
        r = c.post("/license/k-pp-fix/paypal/subscription-link", json={})
    assert r.status_code == 200, r.text
    assert r.json()["approval_url"] == "https://paypal.test/approve"


# ------------------------------------------------------------ Mercado Pago
class FakeMP:
    """Mercado Pago minimo: credenciales de PRUEBA, rechaza cualquier pagador
    que no sea un test_user (o rechaza todo si `reject_all`)."""

    def __init__(self, reject_all=False, pre_id="PRE-OK"):
        self.pre_id = pre_id
        self.reject_all = reject_all
        self.bodies = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if "dolarapi" in str(request.url):
            return httpx.Response(200, json={"venta": 1400})
        if request.url.path == "/users/me":
            return httpx.Response(200, json={"email": "test_user_698@testuser.com", "tags": ["test_user"]})
        body = json.loads(request.content)
        self.bodies.append(body)
        payer = body.get("payer_email", "")
        if self.reject_all or (payer and not payer.endswith("@testuser.com")):
            return httpx.Response(400, json=MP_REAL_OR_TEST)
        return httpx.Response(201, json={"id": self.pre_id, "init_point": "https://mp.test/go"})


@pytest.fixture()
def mpx(monkeypatch):
    monkeypatch.setattr(mp, "MP_ACCESS_TOKEN", "TEST-token")
    monkeypatch.setattr(mp, "MP_TEST_PAYER_EMAIL", "")
    monkeypatch.setattr(mp, "_fx_cache", {"rate": 1400.0, "at": 10**12})
    return monkeypatch


def _mp_create(email):
    return asyncio.run(mp.create_subscription_approval_link("LK1", email))


def test_real_email_with_test_credentials_retries_without_payer_and_succeeds(mpx):
    fake = FakeMP()
    _patch_http(mpx, mp, fake)
    pid, url, amount = _mp_create("manuelangiulli11@gmail.com")
    assert (pid, url) == ("PRE-OK", "https://mp.test/go")
    assert amount == 350000
    assert len(fake.bodies) == 2
    assert fake.bodies[0]["payer_email"] == "manuelangiulli11@gmail.com"
    assert "payer_email" not in fake.bodies[1]
    # el reintento conserva todo lo demas (referencia a la licencia, monto, estado)
    assert fake.bodies[1]["external_reference"] == "LK1" and fake.bodies[1]["status"] == "pending"
    assert fake.bodies[1]["auto_recurring"]["transaction_amount"] == 350000


def test_valid_test_buyer_email_needs_a_single_call(mpx):
    fake = FakeMP()
    _patch_http(mpx, mp, fake)
    assert _mp_create("test_user_123@testuser.com")[0] == "PRE-OK"
    assert len(fake.bodies) == 1


def test_forced_test_payer_email_is_used_and_needs_a_single_call(mpx):
    mpx.setattr(mp, "MP_TEST_PAYER_EMAIL", "test_user_999@testuser.com")
    fake = FakeMP()
    _patch_http(mpx, mp, fake)
    assert _mp_create("manuelangiulli11@gmail.com")[0] == "PRE-OK"
    assert [b["payer_email"] for b in fake.bodies] == ["test_user_999@testuser.com"]


def test_wrongly_forced_payer_email_also_falls_back_to_no_payer(mpx):
    mpx.setattr(mp, "MP_TEST_PAYER_EMAIL", "alguien@gmail.com")  # mal cargada en Render
    fake = FakeMP()
    _patch_http(mpx, mp, fake)
    assert _mp_create(None)[0] == "PRE-OK"
    assert len(fake.bodies) == 2 and "payer_email" not in fake.bodies[1]


def test_no_email_at_all_is_a_single_call(mpx):
    fake = FakeMP()
    _patch_http(mpx, mp, fake)
    assert _mp_create(None)[0] == "PRE-OK"
    assert len(fake.bodies) == 1 and "payer_email" not in fake.bodies[0]


def test_if_mercado_pago_still_refuses_the_error_is_the_full_diagnostic_after_one_retry(mpx):
    fake = FakeMP(reject_all=True)
    _patch_http(mpx, mp, fake)
    with pytest.raises(mp.MercadoPagoError) as exc:
        _mp_create("manuelangiulli11@gmail.com")
    msg = str(exc.value)
    assert "MP_TEST_PAYER_EMAIL" in msg and "de PRUEBA" in msg and "manuelangiulli11@gmail.com" in msg
    assert len(fake.bodies) == 2  # un reintento, jamas un bucle


def test_unrelated_400_is_not_retried(mpx):
    calls = []

    def handler(request):
        if "dolarapi" in str(request.url):
            return httpx.Response(200, json={"venta": 1400})
        calls.append(1)
        return httpx.Response(400, json={"message": "invalid transaction_amount"})

    _patch_http(mpx, mp, handler)
    with pytest.raises(mp.MercadoPagoError, match="rechazo la creacion"):
        _mp_create("manuelangiulli11@gmail.com")
    assert len(calls) == 1


def test_endpoint_returns_200_for_the_real_email_with_test_credentials(mpx):
    fake = FakeMP(pre_id="PRE-REPAIR-EP1")
    _patch_http(mpx, mp, fake)
    with TestClient(main.app) as c:
        assert c.post("/admin/clients", headers=ADMIN, json={"org_name": "A", "license_key": "k-mp-fix"}).status_code == 201
        r = c.post("/license/k-mp-fix/mercadopago/subscription-link", json={"payer_email": "manuelangiulli11@gmail.com"})
    assert r.status_code == 200, r.text
    assert r.json()["approval_url"] == "https://mp.test/go" and r.json()["amount_ars"] == 350000
