"""Tests para app/scanners/gitleaks.py -- construccion de comando,
clasificacion de severidad y parseo de reporte, sin ejecutar gitleaks
de verdad."""
import json
from app.scanners.gitleaks import (
    classify_gitleaks_severity,
    redact_secret_match,
    parse_gitleaks_report,
    _build_gitleaks_cmd,
)


def test_classify_severity_private_key_is_critical():
    assert classify_gitleaks_severity("aws-access-key-id") == "critical"
    assert classify_gitleaks_severity("private-key") == "critical"


def test_classify_severity_token_is_high():
    assert classify_gitleaks_severity("generic-api-key") == "high"
    assert classify_gitleaks_severity("slack-token") == "high"


def test_classify_severity_unknown_rule_is_medium():
    assert classify_gitleaks_severity("algo-sin-marcadores") == "medium"


def test_redact_secret_match_short_secret():
    assert redact_secret_match("abc") == "••••"


def test_redact_secret_match_keeps_prefix_and_suffix():
    redacted = redact_secret_match("ghp_1234567890abcdef")
    assert redacted.startswith("ghp")
    assert redacted.endswith("ef")
    assert "1234567890" not in redacted


def test_parse_gitleaks_report_extracts_findings():
    raw = json.dumps([
        {
            "RuleID": "aws-access-key-id",
            "Description": "AWS Access Key",
            "File": "config/prod.env",
            "StartLine": 12,
            "Commit": "abc123",
            "Secret": "AKIAABCDEFGHIJKLMNOP",
        }
    ])
    findings = parse_gitleaks_report(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert f["file_path"] == "config/prod.env"
    assert f["rule_id"] == "aws-access-key-id"
    assert "AKIAABCDEFGHIJKLMNOP" not in f["match_redacted"]


def test_parse_gitleaks_report_empty_list_returns_empty():
    assert parse_gitleaks_report("[]") == []


def test_parse_gitleaks_report_malformed_returns_empty():
    assert parse_gitleaks_report("no es json <<<") == []


def test_parse_gitleaks_report_non_list_returns_empty():
    assert parse_gitleaks_report(json.dumps({"error": "algo"})) == []


def test_build_cmd_includes_exit_code_zero():
    cmd = _build_gitleaks_cmd("/tmp/repo", "/tmp/report.json", no_git=False)
    assert "--exit-code" in cmd
    assert cmd[cmd.index("--exit-code") + 1] == "0"
    assert "--no-git" not in cmd


def test_build_cmd_adds_no_git_for_plain_directories():
    cmd = _build_gitleaks_cmd("/tmp/repo", "/tmp/report.json", no_git=True)
    assert "--no-git" in cmd
