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
