"""Tests para app/scanners/zeek.py y app/scanners/_duration.py --
logica pura de resolucion de interfaz/duracion y parseo de logs JSON
de zeek, sin ejecutar zeek de verdad (sin captura de red real)."""
import json
from app.scanners._duration import resolve_duration_seconds, MIN_DURATION_MINUTES, MAX_DURATION_MINUTES
from app.scanners.zeek import classify_zeek_notice, resolve_interface, parse_notice_log, summarize_conn_log


def test_resolve_duration_seconds_default():
    assert resolve_duration_seconds({}) == 5 * 60
    assert resolve_duration_seconds(None) == 5 * 60


def test_resolve_duration_seconds_custom_value():
    assert resolve_duration_seconds({"duration_minutes": 10}) == 600


def test_resolve_duration_seconds_clamps_to_max():
    assert resolve_duration_seconds({"duration_minutes": 999}) == MAX_DURATION_MINUTES * 60


def test_resolve_duration_seconds_clamps_to_min():
    assert resolve_duration_seconds({"duration_minutes": 0}) == MIN_DURATION_MINUTES * 60
    assert resolve_duration_seconds({"duration_minutes": -5}) == MIN_DURATION_MINUTES * 60


def test_resolve_duration_seconds_invalid_value_falls_back_to_default():
    assert resolve_duration_seconds({"duration_minutes": "no-es-un-numero"}) == 5 * 60


def test_resolve_interface_explicit_name():
    assert resolve_interface("eth0") == "eth0"


def test_resolve_interface_auto_picks_first_non_loopback():
    result = resolve_interface("auto", list_interfaces=lambda: ["lo", "eth0", "eth1"])
    assert result == "eth0"


def test_resolve_interface_auto_no_interfaces_returns_none():
    result = resolve_interface("auto", list_interfaces=lambda: ["lo"])
    assert result is None


def test_classify_notice_scan_is_high():
    assert classify_zeek_notice("Scan::Port_Scan") == "high"
    assert classify_zeek_notice("Scan::Address_Scan") == "high"


def test_classify_notice_ssl_is_medium():
    assert classify_zeek_notice("SSL::Invalid_Server_Cert") == "medium"


def test_classify_notice_unknown_defaults_to_low():
    assert classify_zeek_notice("Algo::Desconocido") == "low"


def test_parse_notice_log_extracts_findings(tmp_path):
    path = tmp_path / "notice.log"
    path.write_text(
        json.dumps({"note": "Scan::Port_Scan", "msg": "escaneo de puertos detectado", "id.orig_h": "10.0.0.5"}) + "\n"
    )
    findings = parse_notice_log(str(path))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["service"] == "10.0.0.5"


def test_parse_notice_log_missing_file_returns_empty(tmp_path):
    assert parse_notice_log(str(tmp_path / "no-existe.log")) == []


def test_summarize_conn_log_counts_connections_and_hosts(tmp_path):
    path = tmp_path / "conn.log"
    lines = [
        json.dumps({"id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.6"}),
        json.dumps({"id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.7"}),
    ]
    path.write_text("\n".join(lines) + "\n")
    summary = summarize_conn_log(str(path))
    assert "2 conexion" in summary
    assert "3 host" in summary


def test_summarize_conn_log_missing_file():
    summary = summarize_conn_log("/no/existe/conn.log")
    assert "sin conn.log" in summary
