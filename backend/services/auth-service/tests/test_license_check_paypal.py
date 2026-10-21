"""license_check: el link de pago y la cancelacion usan PayPal por defecto."""
import asyncio

import httpx
import pytest

from backend.shared import license_check as lc


def _patch_http(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(lc.httpx, "AsyncClient", factory)
    monkeypatch.setattr(lc, "LICENSE_SERVER_URL", "https://lic.test")
    monkeypatch.setattr(lc, "LICENSE_KEY", "KEY1")


def test_default_provider_is_paypal():
    assert lc.DEFAULT_PROVIDER == "paypal"
    assert lc.provider_label("paypal") == "PayPal"
    assert lc.provider_label("mercadopago") == "Mercado Pago"


def test_get_payment_link_calls_paypal_endpoint(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["body"] = request.content
        return httpx.Response(200, json={"subscription_id": "I-1", "approval_url": "https://paypal.test/ok"})

    _patch_http(monkeypatch, handler)
    url = asyncio.run(lc.get_payment_link("a@b.com"))
    assert url == "https://paypal.test/ok"
    assert seen["url"] == "https://lic.test/license/KEY1/paypal/subscription-link"
    assert b"a@b.com" in seen["body"]


def test_get_payment_link_none_when_server_has_no_paypal(monkeypatch):
    _patch_http(monkeypatch, lambda r: httpx.Response(503))
    assert asyncio.run(lc.get_payment_link("a@b.com")) is None


def test_cancel_subscription_calls_paypal_endpoint(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"cancelled": True})

    _patch_http(monkeypatch, handler)
    asyncio.run(lc.cancel_subscription())
    assert seen["url"] == "https://lic.test/license/KEY1/cancel-subscription"


def test_cancel_surfaces_server_rejection(monkeypatch):
    _patch_http(monkeypatch, lambda r: httpx.Response(404, text="sin suscripcion"))
    with pytest.raises(lc.LicenseCheckError):
        asyncio.run(lc.cancel_subscription())


def test_get_payment_link_409_shows_clear_message(monkeypatch):
    """Ya hay una suscripcion activa: el cliente ve el motivo, no un JSON crudo."""
    _patch_http(monkeypatch, lambda r: httpx.Response(409, json={"detail": "Esta licencia ya tiene una suscripcion de PayPal activa."}))
    with pytest.raises(lc.LicenseCheckError) as exc:
        asyncio.run(lc.get_payment_link("a@b.com"))
    assert str(exc.value) == "Esta licencia ya tiene una suscripcion de PayPal activa."


# --- Mercado Pago (segunda pasarela) -------------------------------------

def test_get_payment_link_mercadopago_calls_its_own_endpoint(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"subscription_id": "P1", "approval_url": "https://mp.test/go", "amount_ars": 1})

    _patch_http(monkeypatch, handler)
    assert asyncio.run(lc.get_payment_link("a@b.com", "mercadopago")) == "https://mp.test/go"
    assert seen["url"] == "https://lic.test/license/KEY1/mercadopago/subscription-link"


def test_unknown_provider_is_rejected_before_any_request(monkeypatch):
    def handler(request):
        raise AssertionError("no deberia hacer ningun request")

    _patch_http(monkeypatch, handler)
    with pytest.raises(lc.LicenseCheckError):
        asyncio.run(lc.get_payment_link("a@b.com", "../admin"))


def test_get_payment_links_returns_each_available_gateway(monkeypatch):
    def handler(request: httpx.Request):
        if "/mercadopago/" in str(request.url):
            return httpx.Response(200, json={"approval_url": "https://mp.test/go"})
        return httpx.Response(200, json={"approval_url": "https://paypal.test/ok"})

    _patch_http(monkeypatch, handler)
    assert asyncio.run(lc.get_payment_links("a@b.com")) == {
        "paypal": "https://paypal.test/ok",
        "mercadopago": "https://mp.test/go",
    }


def test_get_payment_links_skips_a_gateway_that_fails_or_is_unconfigured(monkeypatch):
    def handler(request: httpx.Request):
        if "/mercadopago/" in str(request.url):
            return httpx.Response(503)  # Mercado Pago sin configurar en el servidor central
        return httpx.Response(200, json={"approval_url": "https://paypal.test/ok"})

    _patch_http(monkeypatch, handler)
    assert asyncio.run(lc.get_payment_links("a@b.com")) == {"paypal": "https://paypal.test/ok"}


def test_get_payment_links_empty_when_every_gateway_is_down(monkeypatch):
    _patch_http(monkeypatch, lambda r: httpx.Response(500, text="boom"))
    assert asyncio.run(lc.get_payment_links("a@b.com")) == {}


def test_cancel_falls_back_to_legacy_endpoint_on_an_old_central_server(monkeypatch):
    urls = []

    def handler(request: httpx.Request):
        urls.append(str(request.url))
        if request.url.path.endswith("/paypal/cancel-subscription"):
            return httpx.Response(200, json={"cancelled": True})
        return httpx.Response(404, json={"detail": "Not Found"})  # ruta inexistente

    _patch_http(monkeypatch, handler)
    asyncio.run(lc.cancel_subscription())
    assert urls == [
        "https://lic.test/license/KEY1/cancel-subscription",
        "https://lic.test/license/KEY1/paypal/cancel-subscription",
    ]


def test_cancel_does_not_fall_back_on_a_real_404(monkeypatch):
    urls = []

    def handler(request: httpx.Request):
        urls.append(str(request.url))
        return httpx.Response(404, json={"detail": "esta licencia no tiene ninguna suscripcion vinculada"})

    _patch_http(monkeypatch, handler)
    with pytest.raises(lc.LicenseCheckError):
        asyncio.run(lc.cancel_subscription())
    assert len(urls) == 1


def test_pay_link_request_schema():
    from app.schemas import SubscriptionPayLinkRequest

    assert SubscriptionPayLinkRequest().provider == "paypal"
    assert SubscriptionPayLinkRequest(provider="mercadopago", payer_email="a@b.com").provider == "mercadopago"
    with pytest.raises(Exception):
        SubscriptionPayLinkRequest(provider="bitcoin")
    with pytest.raises(Exception):
        SubscriptionPayLinkRequest(provider="mercadopago", payer_email="no-es-email")


def test_server_rejection_shows_the_readable_detail_not_raw_json(monkeypatch):
    _patch_http(monkeypatch, lambda r: httpx.Response(502, json={"detail": "PayPal rechazo las credenciales (HTTP 401)."}))
    with pytest.raises(lc.LicenseCheckError) as exc:
        asyncio.run(lc.get_payment_link("a@b.com"))
    assert str(exc.value).endswith(": PayPal rechazo las credenciales (HTTP 401).")
    assert "{" not in str(exc.value)


# ---- PAYMENT_PROVIDERS: ofrecer solo algunas pasarelas ----

@pytest.mark.parametrize("raw,expected", [
    ("", ["paypal", "mercadopago"]),
    ("mercadopago", ["mercadopago"]),
    (" MercadoPago ", ["mercadopago"]),
    ("paypal", ["paypal"]),
    ("mercadopago,paypal", ["paypal", "mercadopago"]),
    ("paypal;mercadopago", ["paypal", "mercadopago"]),
    ("mercadopgo", ["paypal", "mercadopago"]),  # error de tipeo: no bloquea los pagos
])
def test_enabled_providers_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("PAYMENT_PROVIDERS", raw)
    assert lc.enabled_providers() == expected


def test_disabled_provider_never_reaches_the_central_server(monkeypatch):
    monkeypatch.setenv("PAYMENT_PROVIDERS", "mercadopago")
    called = []
    _patch_http(monkeypatch, lambda r: called.append(str(r.url)) or httpx.Response(200, json={"approval_url": "https://x.test/a"}))
    with pytest.raises(lc.LicenseCheckError, match="no esta habilitado"):
        asyncio.run(lc.get_payment_link("a@b.com", "paypal"))
    assert called == []


def test_get_payment_links_only_asks_enabled_gateways(monkeypatch):
    monkeypatch.setenv("PAYMENT_PROVIDERS", "mercadopago")
    seen = []

    def handler(request: httpx.Request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"approval_url": "https://mp.test/ok"})

    _patch_http(monkeypatch, handler)
    assert asyncio.run(lc.get_payment_links("a@b.com")) == {"mercadopago": "https://mp.test/ok"}
    assert seen == ["/license/KEY1/mercadopago/subscription-link"]
