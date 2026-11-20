"""missing_bootstrap_entries: detecta los agentes bootstrap (ej. Agente LAN)
que no figuran en la organizacion de un admin. Sin DB."""
import json
from types import SimpleNamespace

from app.services import _hash_agent_key, missing_bootstrap_entries

RAW = json.dumps([
    {"name": "Agente Docker (internet/host)", "key": "k-docker"},
    {"name": "Agente LAN", "key": "k-lan"},
    {"name": "Agente WAN (internet)", "key": "k-wan"},
])


def _agent(key):
    return SimpleNamespace(key_hash=_hash_agent_key(key))


def test_lan_missing_is_reported():
    agents = [_agent("k-docker"), _agent("k-wan")]
    assert [e["name"] for e in missing_bootstrap_entries(agents, RAW)] == ["Agente LAN"]


def test_nothing_missing_when_all_present():
    agents = [_agent("k-docker"), _agent("k-lan"), _agent("k-wan")]
    assert missing_bootstrap_entries(agents, RAW) == []


def test_empty_or_broken_env_reports_nothing():
    assert missing_bootstrap_entries([], "") == []
    assert missing_bootstrap_entries([], "{no json") == []
    assert missing_bootstrap_entries([], json.dumps([{"name": "x"}])) == []


# --- adopcion con varias organizaciones: solo la mas antigua (la del instalador) ---
import asyncio

from app import services as _services


class _Res:
    def __init__(self, v):
        self._v = v

    def scalar_one(self):
        return self._v

    def scalar_one_or_none(self):
        return self._v


class _FakeDb:
    def __init__(self, count, oldest):
        self.count, self.oldest = count, oldest

    async def execute(self, stmt, *a, **k):
        sql = str(stmt)
        if "count(*)" in sql:
            return _Res(self.count)
        return _Res(self.oldest)

    async def flush(self):
        pass


def _run(db, org, monkeypatch):
    async def fake_list(_db, _org):
        return []

    created = []

    async def fake_ensure(_db, name, key, org_id):
        created.append((name, org_id))
        return True

    monkeypatch.setattr(_services, "list_agents", fake_list)
    monkeypatch.setattr(_services, "ensure_bootstrap_agent", fake_ensure)
    result = asyncio.run(_services.adopt_bootstrap_agents(db, RAW, org))
    return result, created


def test_adopta_si_es_la_unica_organizacion(monkeypatch):
    ok, created = _run(_FakeDb(1, "org-a"), "org-a", monkeypatch)
    assert ok and len(created) == 3


def test_adopta_si_es_la_organizacion_mas_antigua(monkeypatch):
    ok, created = _run(_FakeDb(3, "org-a"), "org-a", monkeypatch)
    assert ok and {o for _, o in created} == {"org-a"}


def test_otra_organizacion_no_adopta(monkeypatch):
    ok, created = _run(_FakeDb(3, "org-a"), "org-b", monkeypatch)
    assert not ok and created == []
