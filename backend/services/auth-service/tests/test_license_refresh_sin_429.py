"""'Actualizar estado': pasado el tope de consultas NO devuelve 429 (dejaba el boton
sin responder); devuelve el estado guardado y no vuelve a molestar al servidor central."""
import asyncio
import types

import app.main as m


class _Db:
    async def commit(self):
        pass

    async def refresh(self, _o):
        pass


def _run(monkeypatch, allowed):
    calls = {"central": 0}
    org = types.SimpleNamespace(id="o1")

    async def get_org(db, org_id):
        return org

    async def refresh(db, org_id):
        calls["central"] += 1

    async def limit(key, n, window):
        return allowed

    monkeypatch.setattr(m.services, "get_organization_by_id", get_org)
    monkeypatch.setattr(m.services, "refresh_license_from_central_server", refresh)
    monkeypatch.setattr(m, "check_rate_limit", limit)
    out = asyncio.run(m.refresh_subscription("o1", {"sub": "u1"}, _Db()))
    return out, org, calls


def test_under_limit_asks_central_server(monkeypatch):
    out, org, calls = _run(monkeypatch, True)
    assert out is org and calls["central"] == 1


def test_over_limit_returns_stored_state_without_error(monkeypatch):
    out, org, calls = _run(monkeypatch, False)
    assert out is org and calls["central"] == 0
