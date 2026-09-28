"""Tests de app/services.py::agent_key_matches -- valida que la api key en
texto plano que se manda al LANZAR un escaneo remoto corresponda al agente
elegido (ademas del JWT del usuario). Sin DB: se arma un objeto minimo con
solo el atributo key_hash que agent_key_matches necesita, igual de
aislado que test_delete_status.py con su _FakeStatusEnum."""
from types import SimpleNamespace

from app.services import _hash_agent_key, agent_key_matches


class TestAgentKeyMatches:
    def test_correct_key_matches(self):
        agent = SimpleNamespace(key_hash=_hash_agent_key("la-key-correcta"))
        assert agent_key_matches(agent, "la-key-correcta") is True

    def test_wrong_key_does_not_match(self):
        agent = SimpleNamespace(key_hash=_hash_agent_key("la-key-correcta"))
        assert agent_key_matches(agent, "otra-key-cualquiera") is False

    def test_empty_key_does_not_match(self):
        agent = SimpleNamespace(key_hash=_hash_agent_key("la-key-correcta"))
        assert agent_key_matches(agent, "") is False
