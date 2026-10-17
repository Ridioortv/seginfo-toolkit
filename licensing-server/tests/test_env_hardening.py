"""Los valores pegados en el dashboard de Render suelen traer espacios o saltos
de linea de mas. Un "live " (con espacio) mandaba las credenciales LIVE al
entorno sandbox de PayPal -> HTTP 401 aunque todo "estuviera bien"."""
import importlib
import os
import tempfile

import pytest

os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("LICENSING_DB_PATH", os.path.join(tempfile.mkdtemp(prefix="lic-env-"), "t.db"))

from app import mercadopago as mp, paypal  # noqa: E402


@pytest.fixture()
def reload_modules(monkeypatch):
    def _reload(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        importlib.reload(paypal)
        importlib.reload(mp)

    yield _reload
    monkeypatch.undo()
    importlib.reload(paypal)
    importlib.reload(mp)


def test_paypal_env_with_trailing_space_is_still_live(reload_modules):
    reload_modules(PAYPAL_ENV="live ")
    assert paypal.PAYPAL_ENV == "live"
    assert paypal._base_url() == "https://api-m.paypal.com"


@pytest.mark.parametrize("value", ["LIVE", " Live\n", "production", "prod"])
def test_paypal_env_variants_that_mean_live(reload_modules, value):
    reload_modules(PAYPAL_ENV=value)
    assert paypal._base_url() == "https://api-m.paypal.com"


@pytest.mark.parametrize("value", ["sandbox", "", "  ", "cualquier-cosa"])
def test_everything_else_is_sandbox(reload_modules, value):
    reload_modules(PAYPAL_ENV=value)
    assert paypal._base_url() == "https://api-m.sandbox.paypal.com"


def test_paypal_credentials_are_stripped(reload_modules):
    reload_modules(PAYPAL_CLIENT_ID=" abc \n", PAYPAL_CLIENT_SECRET="\tsecret ", PAYPAL_PLAN_ID=" P-1 ")
    assert (paypal.PAYPAL_CLIENT_ID, paypal.PAYPAL_CLIENT_SECRET, paypal.PAYPAL_PLAN_ID) == ("abc", "secret", "P-1")
    assert paypal.is_configured()


def test_blank_paypal_credentials_are_not_configured(reload_modules):
    reload_modules(PAYPAL_CLIENT_ID="   ", PAYPAL_CLIENT_SECRET="\n")
    assert not paypal.is_configured()


def test_mercadopago_values_are_stripped(reload_modules):
    reload_modules(
        MP_ACCESS_TOKEN=" tok \n", MP_WEBHOOK_SECRET=" s ", MP_NOTIFICATION_URL=" https://x.test/w ",
        MP_FALLBACK_RATE=" 1300 ", MP_FX_FIELD=" venta ",
    )
    assert mp.MP_ACCESS_TOKEN == "tok" and mp.MP_WEBHOOK_SECRET == "s"
    assert mp.MP_NOTIFICATION_URL == "https://x.test/w"
    assert mp.MP_FALLBACK_RATE == "1300" and mp.MP_FX_FIELD == "venta"


def test_blank_mercadopago_token_is_not_configured(reload_modules):
    reload_modules(MP_ACCESS_TOKEN="  \n")
    assert not mp.is_configured()


@pytest.mark.parametrize("value", ["250 USD", "abc", "$250"])
def test_a_badly_typed_number_does_not_stop_the_server_booting(reload_modules, value):
    reload_modules(MP_PRICE_USD=value, MP_FX_MARGIN_PCT=value, MP_FX_MIN=value, MP_FX_MAX=value)
    assert (mp.MP_PRICE_USD, mp.MP_FX_MARGIN_PCT, mp.MP_FX_MIN, mp.MP_FX_MAX) == (250.0, 0.0, 100.0, 100000.0)


def test_numbers_with_a_decimal_comma_are_understood(reload_modules):
    reload_modules(MP_PRICE_USD="250,5")
    assert mp.MP_PRICE_USD == 250.5
    assert mp._valid_rate("1300,50") == 1300.5
    assert mp._valid_rate(" 1300 ") == 1300.0
    assert mp._valid_rate("1.300") is None  # separador de miles: 1,3 -> fuera de rango, se rechaza
    assert mp._valid_rate("") is None


def test_mp_test_payer_email_overrides_payer(reload_modules, monkeypatch):
    """Con MP_TEST_PAYER_EMAIL el pagador siempre es el comprador de prueba,
    aunque el cliente haya escrito (o no) otro email en el modal."""
    import asyncio
    import httpx

    reload_modules(MP_ACCESS_TOKEN="tok", MP_TEST_PAYER_EMAIL=" test_user_123@testuser.com ", MP_FALLBACK_RATE="1000")
    assert mp.MP_TEST_PAYER_EMAIL == "test_user_123@testuser.com"
    sent = []

    def handler(req):
        if req.url.path.endswith("/preapproval"):
            import json
            sent.append(json.loads(req.content))
            return httpx.Response(201, json={"id": "PRE-OVR", "init_point": "https://mp.test/x"})
        return httpx.Response(500)

    real = httpx.AsyncClient
    monkeypatch.setattr(mp.httpx, "AsyncClient", lambda *a, **k: real(*a, transport=httpx.MockTransport(handler), **{x: y for x, y in k.items() if x != "transport"}))
    for given in (None, "real@gmail.com"):
        asyncio.run(mp.create_subscription_approval_link("KEY-OVR", given))
    assert [p["payer_email"] for p in sent] == ["test_user_123@testuser.com"] * 2


def test_mp_without_override_keeps_customer_email(reload_modules):
    reload_modules(MP_TEST_PAYER_EMAIL="")
    assert mp.MP_TEST_PAYER_EMAIL == ""
