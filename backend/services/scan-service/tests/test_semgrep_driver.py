"""Tests para app/scanners/semgrep.py -- construccion de comando y
parseo de JSON, sin ejecutar semgrep de verdad. El chequeo mas
importante de este archivo es que --config NUNCA sea 'auto' ni
'p/...' (ver rules/semgrep/sentinelops-rules.yml para el porque)."""
import json
from app.scanners.semgrep import build_semgrep_cmd, parse_semgrep_json, SEMGREP_RULES_DIR

_SAMPLE_JSON = json.dumps({
    "results": [
        {
            "check_id": "sentinelops-python-eval-exec",
            "path": "app/utils.py",
            "start": {"line": 42},
            "extra": {"message": "uso de eval()", "severity": "ERROR"},
        },
        {
            "check_id": "sentinelops-weak-hash-for-secrets",
            "path": "app/auth.py",
            "start": {"line": 10},
            "extra": {"message": "md5 para password", "severity": "WARNING"},
        },
    ]
})


def test_build_cmd_never_uses_auto_or_registry_config():
    cmd = build_semgrep_cmd("/tmp/repo")
    assert "auto" not in cmd
    assert not any(str(c).startswith("p/") for c in cmd)
    assert "--config" in cmd
    assert cmd[cmd.index("--config") + 1] == SEMGREP_RULES_DIR


def test_build_cmd_disables_metrics():
    cmd = build_semgrep_cmd("/tmp/repo")
    assert "--metrics=off" in cmd


def test_build_cmd_target_path_is_last():
    cmd = build_semgrep_cmd("/tmp/mi-repo")
    assert cmd[-1] == "/tmp/mi-repo"


def test_parse_semgrep_json_extracts_findings():
    findings = parse_semgrep_json(_SAMPLE_JSON)
    assert len(findings) == 2
    error_finding = next(f for f in findings if f["rule_id"] == "sentinelops-python-eval-exec")
    assert error_finding["severity"] == "high"
    assert error_finding["start_line"] == 42
    assert "app/utils.py" in error_finding["title"]


def test_parse_semgrep_json_warning_maps_to_medium():
    findings = parse_semgrep_json(_SAMPLE_JSON)
    warn_finding = next(f for f in findings if f["rule_id"] == "sentinelops-weak-hash-for-secrets")
    assert warn_finding["severity"] == "medium"


def test_parse_semgrep_json_empty_results_returns_empty():
    assert parse_semgrep_json(json.dumps({"results": []})) == []


def test_parse_semgrep_json_malformed_returns_empty():
    assert parse_semgrep_json("no es json <<<") == []
