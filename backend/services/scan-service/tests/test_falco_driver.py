"""Tests para app/scanners/falco.py -- parseo de la salida JSONL de
falco, sin ejecutar el binario de verdad (sin acceso a eBPF/kernel)."""
import json
from app.scanners.falco import parse_falco_jsonl


def test_parse_jsonl_extracts_alert():
    raw = json.dumps({
        "output": "Shell inesperada abierta dentro de un contenedor",
        "priority": "Warning",
        "rule": "Terminal shell in container",
        "output_fields": {"container.name": "scan-service"},
    })
    findings = parse_falco_jsonl(raw)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["service"] == "scan-service"


def test_parse_jsonl_critical_priority():
    raw = json.dumps({"output": "algo critico", "priority": "Critical", "rule": "Regla X"})
    findings = parse_falco_jsonl(raw)
    assert findings[0]["severity"] == "critical"


def test_parse_jsonl_ignores_lines_without_rule():
    # Lineas de log propias de falco (arranque, warnings internos) no
    # tienen la clave "rule" -- no son una alerta real.
    raw = json.dumps({"output": "Falco version x.y.z"})
    assert parse_falco_jsonl(raw) == []


def test_parse_jsonl_skips_malformed_lines():
    raw = "no es json\n" + json.dumps({"output": "ok", "priority": "notice", "rule": "R"})
    findings = parse_falco_jsonl(raw)
    assert len(findings) == 1


def test_parse_jsonl_empty_returns_empty():
    assert parse_falco_jsonl("") == []


def test_parse_jsonl_multiple_lines():
    lines = [
        json.dumps({"output": "a", "priority": "notice", "rule": "R1"}),
        json.dumps({"output": "b", "priority": "error", "rule": "R2"}),
    ]
    findings = parse_falco_jsonl("\n".join(lines))
    assert len(findings) == 2
    assert {f["severity"] for f in findings} == {"low", "high"}
