"""stale_bootstrap_agent_ids: agentes bootstrap que ya no estan en
BOOTSTRAP_AGENTS (ej. el viejo "gvm") se detectan para borrarse; un .env
vacio o roto nunca borra nada. Sin DB."""
import json
from types import SimpleNamespace

from app.services import _hash_agent_key, stale_bootstrap_agent_ids


def _agent(agent_id, key, created_by="bootstrap"):
    return SimpleNamespace(id=agent_id, key_hash=_hash_agent_key(key), created_by=created_by)


RAW = json.dumps([
    {"name": "Agente Docker (internet/host)", "key": "k-docker"},
    {"name": "Agente LAN", "key": "k-lan"},
    {"name": "Agente WAN (internet)", "key": "k-wan"},
])


def test_old_gvm_bootstrap_agent_is_stale():
    agents = [_agent("1", "k-docker"), _agent("2", "k-lan"), _agent("3", "k-wan"), _agent("4", "k-gvm")]
    assert stale_bootstrap_agent_ids(agents, RAW) == ["4"]


def test_manual_agents_are_never_stale():
    agents = [_agent("9", "k-manual", created_by="admin@empresa.com")]
    assert stale_bootstrap_agent_ids(agents, RAW) == []


def test_empty_or_broken_env_never_deletes_anything():
    agents = [_agent("1", "k-gvm")]
    assert stale_bootstrap_agent_ids(agents, "") == []
    assert stale_bootstrap_agent_ids(agents, "{no es json") == []
    assert stale_bootstrap_agent_ids(agents, "[]") == []
    assert stale_bootstrap_agent_ids(agents, json.dumps([{"name": "x"}])) == []


def test_nested_list_in_env_does_not_wipe_legit_agents():
    """Regresion real: un script dejo BOOTSTRAP_AGENTS como
    [[{docker},{lan}],{wan}] y se borraron Docker y LAN por no entender la
    entrada anidada."""
    nested = json.dumps([
        [{"name": "Agente Docker", "key": "k-docker"}, {"name": "Agente LAN", "key": "k-lan"}],
        {"name": "Agente WAN", "key": "k-wan"},
    ])
    agents = [_agent("1", "k-docker"), _agent("2", "k-lan"), _agent("3", "k-wan"), _agent("4", "k-gvm")]
    assert stale_bootstrap_agent_ids(agents, nested) == ["4"]


def test_unreadable_entry_blocks_any_deletion():
    raw = json.dumps([{"name": "Agente Docker", "key": "k-docker"}, {"name": "Agente LAN", "key": 123}])
    raw = raw.replace("123", '["x"]')  # una key que no es texto: entrada que no se entiende
    agents = [_agent("1", "k-docker"), _agent("2", "k-gvm")]
    # hay 2 "key" en el texto pero solo 1 entrada legible -> no se borra nada
    assert stale_bootstrap_agent_ids(agents, raw) == []
