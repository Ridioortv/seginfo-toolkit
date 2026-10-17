"""Un 4xx/5xx de vuln-service al reenviar hallazgos tiene que quedar en el
log (antes se descartaba la respuesta y el fallo era invisible)."""
import logging

import httpx

import app.services as svc


def _resp(status: int, text: str = "") -> httpx.Response:
    return httpx.Response(status, text=text, request=httpx.Request("POST", "http://vuln-service/x"))


def test_rejection_is_logged_with_status_code(caplog):
    with caplog.at_level(logging.WARNING):
        svc._warn_if_ingest_rejected(_resp(500, "Internal Server Error"), "job-1")
    rec = [r for r in caplog.records if "rechazo" in r.getMessage()]
    assert rec and "500" in rec[0].getMessage()
    assert rec[0].job_id == "job-1"


def test_success_is_not_logged(caplog):
    with caplog.at_level(logging.WARNING):
        svc._warn_if_ingest_rejected(_resp(201, "{}"), "job-1")
    assert not caplog.records


def test_body_is_truncated(caplog):
    with caplog.at_level(logging.WARNING):
        svc._warn_if_ingest_rejected(_resp(422, "y" * 5000), "job-1")
    assert len(caplog.records[0].body) <= 200
