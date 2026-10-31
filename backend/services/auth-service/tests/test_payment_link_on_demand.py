"""El login bloqueado (402) ya no crea suscripciones: informa las pasarelas y
entrega un pay_token; el link se genera recien al elegir "Pagar con ..."."""
import asyncio
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import app.main as m
from app.schemas import BlockedPaymentLinkRequest
from backend.shared.security import create_access_token, create_token


class _Org:
    id = "org-1"
    is_active = True
    parent_org_id = None


class _Db:
    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass


REQUEST = SimpleNamespace(client=SimpleNamespace(host="203.0.113.9"))


def _setup(monkeypatch, providers=("paypal", "mercadopago"), link="https://pago.test/x"):
    calls = {"links": [], "audit": []}

    async def fake_link(email, provider="paypal"):
        calls["links"].append((email, provider))
        return link

    async def allowed(_org_id):
        return False  # sin re-chequeo de licencia: el org sigue sin pagar

    async def audit(db, actor, action, resource=""):
        calls["audit"].append((actor, action, resource))

    async def no_limit(key, limit, window_seconds=300):
        return None

    monkeypatch.setattr(m.license_check, "is_configured", lambda: True)
    monkeypatch.setattr(m.license_check, "enabled_providers", lambda: list(providers))
    monkeypatch.setattr(m.license_check, "get_payment_link", fake_link)
    monkeypatch.setattr(m.services, "is_org_active", lambda org: False)
    monkeypatch.setattr(m.services, "record_audit_event", audit)
    monkeypatch.setattr(m, "_license_recheck_allowed", allowed)
    monkeypatch.setattr(m, "_enforce_rate_limit", no_limit)
    return calls


def _blocked_detail(email="cliente@empresa.com"):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(m._reject_if_org_inactive(_Db(), _Org(), email))
    assert exc.value.status_code == 402
    return exc.value.detail


def test_a_blocked_login_creates_no_subscription_and_offers_the_gateways(monkeypatch):
    calls = _setup(monkeypatch)
    detail = _blocked_detail()
    assert calls["links"] == []  # ni una sola suscripcion creada
    assert detail["payment_providers"] == ["paypal", "mercadopago"]
    assert detail["pay_token"]
    assert "payment_urls" not in detail and "payment_url" not in detail


def test_repeated_blocked_logins_still_create_nothing(monkeypatch):
    calls = _setup(monkeypatch)
    for _ in range(5):
        _blocked_detail()
    assert calls["links"] == []


def test_no_gateways_means_contact_the_operator_and_no_token(monkeypatch):
    _setup(monkeypatch, providers=())
    detail = _blocked_detail()
    assert detail["payment_providers"] == [] and detail["pay_token"] is None
    assert "Contacta" in detail["message"]


def test_clicking_a_gateway_creates_exactly_one_link_for_that_gateway(monkeypatch):
    calls = _setup(monkeypatch)
    token = _blocked_detail("pagador@empresa.com")["pay_token"]
    out = asyncio.run(
        m.blocked_login_payment_link(BlockedPaymentLinkRequest(pay_token=token, provider="mercadopago"), REQUEST, _Db())
    )
    assert out.payment_url == "https://pago.test/x"
    assert calls["links"] == [("pagador@empresa.com", "mercadopago")]
    assert calls["audit"][-1] == ("pagador@empresa.com", "auth.login.payment_link", "org-1")


def test_a_gateway_not_enabled_here_is_refused(monkeypatch):
    calls = _setup(monkeypatch, providers=("paypal",))
    token = _blocked_detail()["pay_token"]
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            m.blocked_login_payment_link(BlockedPaymentLinkRequest(pay_token=token, provider="mercadopago"), REQUEST, _Db())
        )
    assert exc.value.status_code == 400 and calls["links"] == []


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda: "x" * 40,  # basura
        lambda: create_access_token("cliente@empresa.com", "admin", org_id="org-1"),  # un access token NO sirve
        lambda: create_token("cliente@empresa.com", timedelta(minutes=5), {"type": "refresh"}),
        lambda: create_token("cliente@empresa.com", timedelta(minutes=-1), {"type": "payment_link", "org_id": "org-1"}),  # vencido
    ],
)
def test_only_a_fresh_payment_token_can_ask_for_a_link(monkeypatch, token_factory):
    calls = _setup(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            m.blocked_login_payment_link(BlockedPaymentLinkRequest(pay_token=token_factory(), provider="paypal"), REQUEST, _Db())
        )
    assert exc.value.status_code == 401 and calls["links"] == []


def test_the_payment_token_is_not_usable_as_an_access_or_refresh_token(monkeypatch):
    from app.dependencies import get_current_claims

    _setup(monkeypatch)
    token = _blocked_detail()["pay_token"]
    with pytest.raises(HTTPException) as exc:
        get_current_claims(token)
    assert exc.value.status_code == 401
    claims = m.decode_token(token)
    assert claims["type"] == "payment_link" and "role" not in claims


def test_central_server_refusal_is_a_502_with_its_reason(monkeypatch):
    _setup(monkeypatch)

    async def refuses(email, provider="paypal"):
        raise m.license_check.LicenseCheckError("Esta licencia ya tiene una suscripcion de PayPal activa.")

    monkeypatch.setattr(m.license_check, "get_payment_link", refuses)
    token = _blocked_detail()["pay_token"]
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            m.blocked_login_payment_link(BlockedPaymentLinkRequest(pay_token=token, provider="paypal"), REQUEST, _Db())
        )
    assert exc.value.status_code == 502 and "ya tiene una suscripcion" in exc.value.detail
