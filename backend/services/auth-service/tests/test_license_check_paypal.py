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
    assert lc.PAYMENT_PROVIDER == "paypal"
    assert lc.PROVIDER_LABEL == "PayPal"


def test_get_payment_link_calls_paypal_endpoint(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["body"] = request.content
        return httpx.Response(200, json={"subscription_id": "I-1", "approval_url": "https://paypal.test/ok"})

    _patch_http(monkeypatch, handler)
    monkeypatch.setattr(lc, "PAYMENT_PROVIDER", "paypal")
    url = asyncio.run(lc.get_payment_link("a@b.com"))
    assert url == "https://paypal.test/ok"
    assert seen["url"] == "https://lic.test/license/KEY1/paypal/subscription-link"
    assert b"a@b.com" in seen["body"]


def test_get_payment_link_none_when_server_has_no_paypal(monkeypatch):
    _patch_http(monkeypatch, lambda r: httpx.Response(503))
    monkeypatch.setattr(lc, "PAYMENT_PROVIDER", "paypal")
    assert asyncio.run(lc.get_payment_link("a@b.com")) is None


def test_cancel_subscription_calls_paypal_endpoint(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"cancelled": True})

    _patch_http(monkeypatch, handler)
    monkeypatch.setattr(lc, "PAYMENT_PROVIDER", "paypal")
    asyncio.run(lc.cancel_subscription())
    assert seen["url"] == "https://lic.test/license/KEY1/paypal/cancel-subscription"


def test_cancel_surfaces_server_rejection(monkeypatch):
    _patch_http(monkeypatch, lambda r: httpx.Response(404, text="sin suscripcion"))
    monkeypatch.setattr(lc, "PAYMENT_PROVIDER", "paypal")
    with pytest.raises(lc.LicenseCheckError):
        asyncio.run(lc.cancel_subscription())


def test_mercadopago_provider_still_available(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"init_point": "https://mp.test/x"})

    _patch_http(monkeypatch, handler)
    monkeypatch.setattr(lc, "PAYMENT_PROVIDER", "mercadopago")
    assert asyncio.run(lc.get_payment_link("a@b.com")) == "https://mp.test/x"
    assert seen["url"].endswith("/mercadopago/subscription-link")
