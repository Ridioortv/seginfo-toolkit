"""Tests para app/services.py::_findings_to_siem_events -- la traduccion
de findings de un scan a eventos ECS-lite para siem-service. Funcion
pura, sin DB ni red."""
from app.services import _findings_to_siem_events


class TestFindingsToSiemEvents:
    def test_one_event_per_finding(self):
        findings = [{"title": "Puerto 22 abierto", "severity": "low"}, {"title": "Puerto 23 abierto", "severity": "high"}]
        events = _findings_to_siem_events("nmap", "192.168.1.10", "asset-1", findings)
        assert len(events) == 2

    def test_event_carries_target_scanner_and_severity(self):
        findings = [{"title": "OpenSSL vulnerable", "severity": "critical"}]
        events = _findings_to_siem_events("trivy", "10.0.0.5", "asset-9", findings)
        event = events[0]
        assert event["host"] == "10.0.0.5"
        assert event["source_type"] == "trivy"
        assert event["severity"] == "critical"
        assert event["asset_id"] == "asset-9"
        assert event["event_category"] == "vulnerability"
        assert event["message"] == "OpenSSL vulnerable"

    def test_missing_severity_defaults_to_info(self):
        events = _findings_to_siem_events("nmap", "10.0.0.1", None, [{"title": "Puerto abierto"}])
        assert events[0]["severity"] == "info"

    def test_no_findings_returns_empty_list(self):
        assert _findings_to_siem_events("nmap", "10.0.0.1", None, []) == []
