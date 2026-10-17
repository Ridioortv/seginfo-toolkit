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
