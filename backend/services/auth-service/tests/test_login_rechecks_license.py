"""Despues de pagar, el login bloqueado (402) vuelve a consultar al servidor
central antes de rechazar: si la licencia ya se extendio, deja entrar en el acto
(antes habia que esperar al chequeo periodico de LICENSE_CHECK_INTERVAL_HOURS)."""
import asyncio
import pytest
from fastapi import HTTPException

import app.main as m


class _Org:
    id = "org-1"


class _Db:
    def __init__(self):
        self.commits = 0

    async def commit(self):
        self.commits += 1

    async def refresh(self, _obj):
        pass


def _setup(monkeypatch, paid_at_central: bool):
    state = {"active": False, "refreshed": 0, "links": 0}

    async def fake_refresh(db, org_id):
        state["refreshed"] += 1
        state["active"] = paid_at_central

    async def fake_links(email):
        state["links"] += 1
        return {"mercadopago": "https://pago"}

    async def allowed(_org_id):
        return True

    async def audit(*a, **k):
        pass

    monkeypatch.setattr(m.license_check, "is_configured", lambda: True)
    monkeypatch.setattr(m.license_check, "get_payment_links", fake_links)
    monkeypatch.setattr(m.services, "is_org_active", lambda org: state["active"])
    monkeypatch.setattr(m.services, "refresh_license_from_central_server", fake_refresh)
    monkeypatch.setattr(m.services, "record_audit_event", audit)
    monkeypatch.setattr(m, "_license_recheck_allowed", allowed)
    return state


def test_login_lets_in_right_after_paying(monkeypatch):
    state = _setup(monkeypatch, paid_at_central=True)
    asyncio.run(m._reject_if_org_inactive(_Db(), _Org(), "cliente@empresa.com"))  # no levanta 402
    assert state["refreshed"] == 1
    assert state["links"] == 0  # no se generan links de pago innecesarios


def test_login_still_blocked_when_not_paid(monkeypatch):
    state = _setup(monkeypatch, paid_at_central=False)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(m._reject_if_org_inactive(_Db(), _Org(), "cliente@empresa.com"))
    assert exc.value.status_code == 402
    assert state["refreshed"] == 1
    assert exc.value.detail["payment_urls"] == {"mercadopago": "https://pago"}
