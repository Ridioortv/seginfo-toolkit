"""Tests para app/scanners/zap.py -- parseo del reporte JSON de ZAP,
sin ejecutar zap.sh de verdad."""
import json
from app.scanners.zap import parse_zap_report


_SAMPLE_REPORT = json.dumps({
    "site": [
        {
            "@name": "https://app.cliente.com",
            "alerts": [
                {
                    "name": "Cross Site Scripting (Reflected)",
                    "riskdesc": "High (Medium)",
                    "desc": "descripcion del hallazgo",
                    "cweid": "79",
                    "instances": [{"uri": "https://app.cliente.com/search?q=1"}],
                },
                {
                    "name": "X-Content-Type-Options Header Missing",
                    "riskdesc": "Low (Medium)",
                    "desc": "falta el header",
                    "cweid": "-1",
                    "instances": [],
                },
            ],
        }
    ]
})


def test_parse_report_extracts_alerts():
    findings = parse_zap_report(_SAMPLE_REPORT)
    assert len(findings) == 2


def test_parse_report_maps_risk_to_severity():
    findings = parse_zap_report(_SAMPLE_REPORT)
    xss = next(f for f in findings if "Cross Site Scripting" in f["title"])
    assert xss["severity"] == "high"
    assert xss["cwe_id"] == "CWE-79"


def test_parse_report_low_risk_maps_to_low():
    findings = parse_zap_report(_SAMPLE_REPORT)
    header = next(f for f in findings if "Header Missing" in f["title"])
    assert header["severity"] == "low"
    assert header["cwe_id"] is None


def test_parse_report_includes_instance_uri_as_service():
    findings = parse_zap_report(_SAMPLE_REPORT)
    xss = next(f for f in findings if "Cross Site Scripting" in f["title"])
    assert "app.cliente.com/search" in xss["service"]


def test_parse_report_malformed_returns_empty():
    assert parse_zap_report("no es json <<<") == []


def test_parse_report_empty_returns_empty():
    assert parse_zap_report("") == []
