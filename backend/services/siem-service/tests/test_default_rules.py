"""Tests de app/services.py::DEFAULT_RULES -- verifica que cada regla
recomendada (las que carga POST /rules/seed-defaults) realmente hace match
contra un evento ECS-lite del tipo que le manda scan-service, y que NO
hace falso positivo con severidades mas bajas. Usa el motor real
(app.sigma.evaluate_rule), sin DB ni red."""
from app.ecs import normalize_event
from app.services import DEFAULT_RULES
from app.sigma import evaluate_rule


def _rule_by_name(name: str) -> dict:
    return next(r for r in DEFAULT_RULES if r["name"] == name)


def _scan_event(severity: str) -> dict:
    return normalize_event(
        {
            "host": "192.168.1.10",
            "event_action": "scan_finding",
            "event_category": "vulnerability",
            "severity": severity,
            "message": "Puerto 23 (telnet) abierto",
            "source_type": "nmap",
        },
        organization_id="org-1",
    )


class TestCriticalScanFindingRule:
    def test_matches_a_critical_finding(self):
        rule = _rule_by_name("Hallazgo critico de escaneo")
        assert evaluate_rule(_scan_event("critical"), rule["detection"]) is True

    def test_does_not_match_a_high_or_medium_finding(self):
        rule = _rule_by_name("Hallazgo critico de escaneo")
        assert evaluate_rule(_scan_event("high"), rule["detection"]) is False
        assert evaluate_rule(_scan_event("medium"), rule["detection"]) is False


class TestHighScanFindingRule:
    def test_matches_a_high_finding(self):
        rule = _rule_by_name("Hallazgo alto de escaneo")
        assert evaluate_rule(_scan_event("high"), rule["detection"]) is True

    def test_does_not_match_a_critical_or_low_finding(self):
        rule = _rule_by_name("Hallazgo alto de escaneo")
        assert evaluate_rule(_scan_event("critical"), rule["detection"]) is False
        assert evaluate_rule(_scan_event("low"), rule["detection"]) is False


class TestAdminLoginFailureRule:
    def test_matches_failed_admin_login(self):
        rule = _rule_by_name("Login fallido repetido en cuenta administrativa")
        event = normalize_event(
            {"event_action": "user_login", "event_outcome": "failure", "user": "root"},
            organization_id="org-1",
        )
        assert evaluate_rule(event, rule["detection"]) is True

    def test_does_not_match_a_non_admin_user(self):
        rule = _rule_by_name("Login fallido repetido en cuenta administrativa")
        event = normalize_event(
            {"event_action": "user_login", "event_outcome": "failure", "user": "juan"},
            organization_id="org-1",
        )
        assert evaluate_rule(event, rule["detection"]) is False


class TestAllDefaultRulesAreWellFormed:
    def test_every_rule_has_a_name_and_a_valid_condition(self):
        for rule in DEFAULT_RULES:
            assert rule["name"]
            assert rule["detection"].get("condition")
            # Toda selection referenciada en la condition debe existir --
            # si no, evaluate_rule() nunca podria devolver True.
            assert "selection_1" in rule["detection"]
