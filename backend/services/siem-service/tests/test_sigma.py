"""Tests para app/sigma.py: el motor de reglas estilo Sigma que evalua
`condition` contra eventos ya normalizados (ECS). 100% local (sin
OpenSearch, sin red) -- es puro analisis sobre datos declarados, nunca
ejecuta nada.
"""
from app.sigma import evaluate_rule, _safe_eval_condition, _field_matches


class TestFieldMatches:
    def test_exact_match_case_insensitive(self):
        assert _field_matches("Admin", "admin") is True

    def test_no_match(self):
        assert _field_matches("user1", "admin") is False

    def test_wildcard_match(self):
        assert _field_matches("C:\\Windows\\System32\\cmd.exe", "*cmd.exe") is True

    def test_list_of_expected_is_or(self):
        assert _field_matches("root", ["admin", "root"]) is True
        assert _field_matches("bob", ["admin", "root"]) is False

    def test_none_event_value_does_not_match_non_empty_expected(self):
        assert _field_matches(None, "admin") is False


class TestEvaluateRule:
    def _event(self, **overrides):
        event = {
            "event": {"action": "user_login", "outcome": "failure"},
            "user": {"name": "root"},
        }
        event.update(overrides)
        return event

    def test_and_condition_matches(self):
        detection = {
            "selection_login_failure": {"event.action": "user_login", "event.outcome": "failure"},
            "selection_admin_targets": {"user.name": ["admin", "root"]},
            "condition": "selection_login_failure and selection_admin_targets",
        }
        assert evaluate_rule(self._event(), detection) is True

    def test_and_condition_fails_when_one_selection_fails(self):
        detection = {
            "selection_login_failure": {"event.action": "user_login", "event.outcome": "failure"},
            "selection_admin_targets": {"user.name": ["admin"]},  # root no esta en la lista
            "condition": "selection_login_failure and selection_admin_targets",
        }
        assert evaluate_rule(self._event(), detection) is False

    def test_or_condition(self):
        detection = {
            "selection_a": {"user.name": "nadie"},
            "selection_b": {"user.name": "root"},
            "condition": "selection_a or selection_b",
        }
        assert evaluate_rule(self._event(), detection) is True

    def test_not_condition(self):
        detection = {
            "selection_a": {"user.name": "nadie"},
            "condition": "not selection_a",
        }
        assert evaluate_rule(self._event(), detection) is True

    def test_missing_condition_never_matches(self):
        detection = {"selection_a": {"user.name": "root"}}
        assert evaluate_rule(self._event(), detection) is False

    def test_missing_selections_never_matches(self):
        detection = {"condition": "selection_a"}
        assert evaluate_rule(self._event(), detection) is False

    def test_unknown_field_in_event_does_not_match(self):
        detection = {
            "selection_a": {"process.name": "mimikatz.exe"},
            "condition": "selection_a",
        }
        assert evaluate_rule(self._event(), detection) is False


class TestSafeEvalConditionIsSandboxed:
    """La condicion se parsea a AST y se restringe a and/or/not/nombres de
    selection -- nunca un eval() sobre texto arbitrario. Estos tests
    confirman que un intento de escapar la sandbox (acceso a atributos,
    llamadas a funciones, imports) se rechaza en vez de ejecutarse."""

    def test_rejects_function_call(self):
        assert _safe_eval_condition("selection_a()", {"selection_a": True}) is False

    def test_rejects_attribute_access(self):
        assert _safe_eval_condition("selection_a.__class__", {"selection_a": True}) is False

    def test_rejects_import_like_expression(self):
        assert _safe_eval_condition("__import__('os')", {}) is False

    def test_rejects_invalid_syntax(self):
        assert _safe_eval_condition("selection_a and (", {"selection_a": True}) is False

    def test_rejects_unknown_name(self):
        assert _safe_eval_condition("selection_desconocida", {"selection_a": True}) is False

    def test_accepts_valid_boolean_expression(self):
        assert _safe_eval_condition(
            "(selection_a or selection_b) and not selection_c",
            {"selection_a": True, "selection_b": False, "selection_c": False},
        ) is True
