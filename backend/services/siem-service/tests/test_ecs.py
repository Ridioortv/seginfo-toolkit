"""Tests para app/ecs.py: normalizacion de eventos crudos al subconjunto de
ECS que usa SentinelOps, y el helper get_by_path que usa sigma.py para leer
campos anidados. Pura transformacion de datos, sin red ni OpenSearch."""
from app.ecs import normalize_event, get_by_path


class TestNormalizeEvent:
    def test_maps_known_fields(self):
        raw = {
            "host": "web-01",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.1",
            "user": "root",
            "event_action": "user_login",
            "event_category": "authentication",
            "event_outcome": "failure",
            "message": "login failed",
        }
        doc = normalize_event(raw, organization_id="org-1")
        assert doc["organization_id"] == "org-1"
        assert doc["host"]["name"] == "web-01"
        assert doc["source"]["ip"] == "10.0.0.5"
        assert doc["destination"]["ip"] == "10.0.0.1"
        assert doc["user"]["name"] == "root"
        assert doc["event"] == {"action": "user_login", "category": "authentication", "outcome": "failure"}
        assert doc["message"] == "login failed"

    def test_missing_fields_default_to_empty_string_not_none(self):
        doc = normalize_event({})
        assert doc["host"]["name"] == ""
        assert doc["source"]["ip"] == ""
        assert doc["user"]["name"] == ""
        assert doc["event"]["action"] == ""

    def test_timestamp_defaults_to_now_when_missing(self):
        doc = normalize_event({})
        assert doc["@timestamp"]  # no vacio

    def test_explicit_timestamp_is_preserved(self):
        doc = normalize_event({"timestamp": "2026-01-01T00:00:00Z"})
        assert doc["@timestamp"] == "2026-01-01T00:00:00Z"

    def test_source_type_defaults_to_generic(self):
        doc = normalize_event({})
        assert doc["sentinelops"]["source_type"] == "generic"


class TestGetByPath:
    def test_nested_path(self):
        doc = {"event": {"action": "user_login"}}
        assert get_by_path(doc, "event.action") == "user_login"

    def test_missing_path_returns_none(self):
        doc = {"event": {}}
        assert get_by_path(doc, "event.action") is None

    def test_missing_top_level_key_returns_none(self):
        assert get_by_path({}, "event.action") is None

    def test_path_through_non_dict_returns_none(self):
        doc = {"event": "no-es-un-dict"}
        assert get_by_path(doc, "event.action") is None
