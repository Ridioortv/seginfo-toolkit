"""Tests de app/services.py: is_protected_agent (los agentes bootstrap --
Agente Docker/Agente LAN, ver ensure_bootstrap_agent -- no se pueden
borrar desde la UI) y resolve_bootstrap_api_key (la UI necesita la api
key en texto plano de esos agentes para poder lanzar un escaneo remoto
con ellos, ya que nunca se registran a mano). Sin DB: se arman objetos
minimos con solo los atributos que estas funciones necesitan, igual de
aislado que test_agent_key_matches.py."""
import json
from types import SimpleNamespace

from app.services import _hash_agent_key, is_protected_agent, resolve_bootstrap_api_key


def _agent(created_by, key_hash=""):
    return SimpleNamespace(created_by=created_by, key_hash=key_hash)


class TestIsProtectedAgent:
    def test_bootstrap_agent_is_protected(self):
        assert is_protected_agent(_agent("bootstrap")) is True

    def test_manually_created_agent_is_not_protected(self):
        assert is_protected_agent(_agent("admin@empresa.com")) is False
        assert is_protected_agent(_agent("")) is False


class TestResolveBootstrapApiKey:
    _BOOTSTRAP_RAW = json.dumps([
        {"name": "Agente Docker (internet/host)", "key": "key-docker-123"},
        {"name": "Agente LAN", "key": "key-lan-456"},
    ])

    def test_resolves_key_for_matching_bootstrap_agent(self):
        agent = _agent("bootstrap", key_hash=_hash_agent_key("key-lan-456"))
        assert resolve_bootstrap_api_key(agent, self._BOOTSTRAP_RAW) == "key-lan-456"

    def test_non_bootstrap_agent_never_resolves_a_key(self):
        # Aunque el hash coincida por casualidad, un agente creado a mano
        # (created_by != "bootstrap") nunca debe devolver una key --
        # nunca deberia coincidir en la practica (la key la elige el
        # servidor al azar), pero la funcion no debe confiar en eso.
        agent = _agent("admin@empresa.com", key_hash=_hash_agent_key("key-lan-456"))
        assert resolve_bootstrap_api_key(agent, self._BOOTSTRAP_RAW) is None

    def test_bootstrap_agent_with_no_matching_hash_returns_none(self):
        # Puede pasar si BOOTSTRAP_AGENTS cambio despues de crear el agente.
        agent = _agent("bootstrap", key_hash=_hash_agent_key("otra-key-cualquiera"))
        assert resolve_bootstrap_api_key(agent, self._BOOTSTRAP_RAW) is None

    def test_empty_bootstrap_agents_env_returns_none(self):
        agent = _agent("bootstrap", key_hash=_hash_agent_key("key-lan-456"))
        assert resolve_bootstrap_api_key(agent, "") is None

    def test_malformed_json_returns_none_instead_of_raising(self):
        agent = _agent("bootstrap", key_hash=_hash_agent_key("key-lan-456"))
        assert resolve_bootstrap_api_key(agent, "no es json <<<") is None
