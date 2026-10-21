"""Un fallo al hablar con PayPal / Mercado Pago nunca debe ser un 500 mudo
("Internal Server Error"): tiene que llegar como 502 con el motivo."""
import os
import tempfile

import httpx
import pytest

_tmp = tempfile.mkdtemp(prefix="lic-gw-test-")
os.environ["ADMIN_TOKEN"] = "test-admin-token"
os.environ["LICENSING_DB_PATH"] = os.path.join(_tmp, "t.db")
os.environ.pop("DATABASE_URL", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import main, mercadopago as mp, paypal  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}


@pytest.fixture()
def client(monkeypatch):
    with TestClient(main.app, raise_server_exceptions=False) as c:
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_ID", "id")
        monkeypatch.setattr(paypal, "PAYPAL_CLIENT_SECRET", "secret")
        monkeypatch.setattr(paypal, "PAYPAL_PLAN_ID", "P-1")
        monkeypatch.setattr(mp, "MP_ACCESS_TOKEN", "token")
        monkeypatch.setattr(mp, "_fx_cache", {"rate": 1500.0, "at": 10**12})
        yield c


def _patch_http(monkeypatch, module, handler):
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)


def _new(c, key):
    assert c.post("/admin/clients", headers=ADMIN, json={"org_name": "A", "license_key": key}).status_code == 201


def test_paypal_bad_credentials_is_502_with_a_clear_reason(client, monkeypatch):
    _new(client, "k-g1")
    _patch_http(monkeypatch, paypal, lambda r: httpx.Response(401, json={"error": "invalid_client"}))
    r = client.post("/license/k-g1/paypal/subscription-link", json={})
    assert r.status_code == 502
    assert "credenciales" in r.json()["detail"] and "PAYPAL_ENV" in r.json()["detail"]
    assert "secret" not in r.text.replace("PAYPAL_CLIENT_SECRET", "")


def test_paypal_network_failure_is_502_not_500(client, monkeypatch):
    _new(client, "k-g2")

    def boom(request):
        raise httpx.ConnectError("sin red")

    _patch_http(monkeypatch, paypal, boom)
    r = client.post("/license/k-g2/paypal/subscription-link", json={})
    assert r.status_code == 502
    assert "ConnectError" in r.json()["detail"]


def test_mercadopago_bad_token_is_502_with_a_clear_reason(client, monkeypatch):
    _new(client, "k-g3")
    _patch_http(monkeypatch, mp, lambda r: httpx.Response(401, json={"message": "invalid access token"}))
    r = client.post("/license/k-g3/mercadopago/subscription-link", json={})
    assert r.status_code == 502
    assert "MP_ACCESS_TOKEN" in r.json()["detail"]


def test_mercadopago_network_failure_is_502_not_500(client, monkeypatch):
    _new(client, "k-g4")

    def boom(request):
        raise httpx.ConnectTimeout("lento")

    _patch_http(monkeypatch, mp, boom)
    r = client.post("/license/k-g4/mercadopago/subscription-link", json={})
    assert r.status_code == 502


def test_broken_paypal_does_not_block_a_mercadopago_link(client, monkeypatch):
    """Antes: con las credenciales de PayPal mal, el chequeo de doble cobro
    fallaba y el link de Mercado Pago tambien salia con el error de PayPal."""
    from app import db

    _new(client, "k-g5")
    db.set_paypal_subscription_id("k-g5", "I-GW5")

    async def broken(_id):
        raise paypal.PayPalError("PayPal rechazo las credenciales (HTTP 401).")

    async def fake_create(license_key, payer_email=None):
        return "PRE-OK", "https://mp.test/go", 375000

    monkeypatch.setattr(paypal, "get_subscription_status", broken)
    monkeypatch.setattr(mp, "create_subscription_approval_link", fake_create)
    r = client.post("/license/k-g5/mercadopago/subscription-link", json={})
    assert r.status_code == 200
    assert r.json()["approval_url"] == "https://mp.test/go"


def test_broken_mercadopago_does_not_block_a_paypal_link(client, monkeypatch):
    from app import db

    _new(client, "k-g6")
    db.set_mp_preapproval_id("k-g6", "PRE-GW6")

    async def broken(_id):
        raise mp.MercadoPagoError("token invalido")

    async def fake_create(license_key, plan_id=None, payer_email=None):
        return "I-OK", "https://paypal.test/ok"

    monkeypatch.setattr(mp, "get_subscription_status", broken)
    monkeypatch.setattr(paypal, "create_subscription_approval_link", fake_create)
    r = client.post("/license/k-g6/paypal/subscription-link", json={})
    assert r.status_code == 200


def test_broken_paypal_still_reports_its_own_error_for_a_paypal_link(client, monkeypatch):
    from app import db

    _new(client, "k-g7")
    db.set_paypal_subscription_id("k-g7", "I-GW7")

    async def broken(_id):
        raise paypal.PayPalError("PayPal rechazo las credenciales (HTTP 401).")

    monkeypatch.setattr(paypal, "get_subscription_status", broken)
    r = client.post("/license/k-g7/paypal/subscription-link", json={})
    assert r.status_code == 502 and "credenciales" in r.json()["detail"]


def test_mercadopago_real_vs_test_users_mismatch_explains_what_to_do(client, monkeypatch):
    """Caso real: token de PRUEBA + email de un usuario real -> Mercado Pago
    responde 400 "Both payer and collector must be real or test users"."""
    _new(client, "k-g8")

    def handler(request):
        if "dolarapi" in str(request.url):
            return httpx.Response(200, json={"venta": 1500})
        return httpx.Response(400, json={"message": "Both payer and collector must be real or test users", "status": 400})

    _patch_http(monkeypatch, mp, handler)
    r = client.post("/license/k-g8/mercadopago/subscription-link", json={"payer_email": "real@gmail.com"})
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert "COMPRADOR de prueba" in detail and "produccion" in detail
    assert "real or test" not in detail


def _mismatch_handler(me_json, me_status=200):
    def handler(request):
        u = str(request.url)
        if "dolarapi" in u:
            return httpx.Response(200, json={"venta": 1500})
        if u.endswith("/users/me"):
            return httpx.Response(me_status, json=me_json)
        return httpx.Response(400, json={"message": "Both payer and collector must be real or test users", "status": 400})
    return handler


def test_mismatch_diagnostic_reports_test_credentials_and_payer_sent(client, monkeypatch):
    _new(client, "k-g9")
    _patch_http(monkeypatch, mp, _mismatch_handler({"email": "test_user_555@testuser.com", "tags": ["test_user"]}))
    monkeypatch.setattr(mp, "MP_TEST_PAYER_EMAIL", "")
    d = client.post("/license/k-g9/mercadopago/subscription-link", json={"payer_email": "real@gmail.com"}).json()["detail"]
    assert "credenciales de PRUEBA" in d and "test_user_555@testuser.com" in d
    assert "real@gmail.com (de el email del modal)" in d
    assert len(d) < 480  # el cliente on-prem recorta a 500


def test_mismatch_diagnostic_shows_which_env_payer_was_used(client, monkeypatch):
    _new(client, "k-g10")
    _patch_http(monkeypatch, mp, _mismatch_handler({"email": "test_user_555@testuser.com", "tags": ["test_user"]}))
    monkeypatch.setattr(mp, "MP_TEST_PAYER_EMAIL", "test_user_999@testuser.com")
    d = client.post("/license/k-g10/mercadopago/subscription-link", json={}).json()["detail"]
    assert "test_user_999@testuser.com (de MP_TEST_PAYER_EMAIL)" in d


def test_mismatch_diagnostic_never_leaks_real_seller_email(client, monkeypatch):
    _new(client, "k-g11")
    _patch_http(monkeypatch, mp, _mismatch_handler({"email": "dueno@empresa.com", "tags": []}))
    monkeypatch.setattr(mp, "MP_TEST_PAYER_EMAIL", "")
    d = client.post("/license/k-g11/mercadopago/subscription-link", json={}).json()["detail"]
    assert "credenciales REALES" in d and "dueno@empresa.com" not in d and "pagador enviado: ninguno" in d


def test_mismatch_diagnostic_survives_users_me_failure(client, monkeypatch):
    _new(client, "k-g12")
    _patch_http(monkeypatch, mp, _mismatch_handler({"message": "x"}, me_status=500))
    d = client.post("/license/k-g12/mercadopago/subscription-link", json={}).json()["detail"]
    assert "no se pudo detectar" in d and "MP_TEST_PAYER_EMAIL" in d


def _bad_request_handler(allow_without_email: bool, seen: list):
    def handler(request):
        u = str(request.url)
        if "dolarapi" in u:
            return httpx.Response(200, json={"venta": 1500})
        import json as _j
        body = _j.loads(request.content)
        seen.append(body.get("payer_email"))
        if "payer_email" in body:
            return httpx.Response(400, json={"message": "User bad request", "status": 400})
        if allow_without_email:
            return httpx.Response(201, json={"id": "PRE-NOEMAIL", "init_point": "https://mp.test/checkout"})
        return httpx.Response(400, json={"message": "payer_email is required", "status": 400})
    return handler


def test_user_bad_request_retries_without_payer_email_and_succeeds(client, monkeypatch):
    _new(client, "k-g13")
    seen: list = []
    _patch_http(monkeypatch, mp, _bad_request_handler(True, seen))
    monkeypatch.setattr(mp, "MP_TEST_PAYER_EMAIL", "test_user_1@testuser.com")
    r = client.post("/license/k-g13/mercadopago/subscription-link", json={})
    assert r.status_code == 200 and r.json()["approval_url"] == "https://mp.test/checkout"
    assert seen == ["test_user_1@testuser.com", None]


def test_user_bad_request_when_retry_also_fails_explains_the_email(client, monkeypatch):
    _new(client, "k-g14")
    seen: list = []
    _patch_http(monkeypatch, mp, _bad_request_handler(False, seen))
    monkeypatch.setattr(mp, "MP_TEST_PAYER_EMAIL", "test_user_1@testuser.com")
    r = client.post("/license/k-g14/mercadopago/subscription-link", json={})
    assert r.status_code == 502
    d = r.json()["detail"]
    assert "test_user_1@testuser.com (de MP_TEST_PAYER_EMAIL)" in d and "sin la palabra TESTUSER" in d
    assert len(d) < 480


FOREIGN = {"message": "the preapprovalId is not valid for callerId", "status": 400}


def test_mp_link_ignores_a_preapproval_left_over_from_test_mode(client, monkeypatch):
    """Una suscripcion creada con credenciales de prueba queda guardada en la
    licencia; con el token de produccion MP la rechaza con 400 "not valid for
    callerId". No debe bloquear la generacion del link nuevo."""
    _new(client, "k-g-foreign")
    main.db.set_mp_preapproval_id("k-g-foreign", "old-test-preapproval")
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.method == "GET" and request.url.path.endswith("/preapproval/old-test-preapproval"):
            return httpx.Response(400, json=FOREIGN)
        if request.method == "POST" and request.url.path.endswith("/preapproval"):
            return httpx.Response(201, json={"id": "new-live-id", "init_point": "https://mp/checkout?id=new-live-id"})
        return httpx.Response(500, json={})

    _patch_http(monkeypatch, mp, handler)
    r = client.post("/license/k-g-foreign/mercadopago/subscription-link", json={})
    assert r.status_code == 200, r.text
    assert r.json()["subscription_id"] == "new-live-id"
    assert main.db.get_client("k-g-foreign")["mp_preapproval_id"] == "new-live-id"


def test_mp_get_preapproval_other_400_is_still_an_error(client, monkeypatch):
    _patch_http(monkeypatch, mp, lambda r: httpx.Response(400, json={"message": "otra cosa", "status": 400}))
    import asyncio

    with pytest.raises(mp.MercadoPagoError):
        asyncio.run(mp.get_preapproval("x"))


def test_mp_cancel_of_a_foreign_preapproval_is_not_an_error(client, monkeypatch):
    _patch_http(monkeypatch, mp, lambda r: httpx.Response(400, json=FOREIGN))
    import asyncio

    asyncio.run(mp.cancel_subscription("old-test-preapproval"))
