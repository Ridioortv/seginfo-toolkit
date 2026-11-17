"""Nucleo del auditor de salidas (backend/shared/egress.py): que es interno, que se anota, que bloquea el modo
aislado y como se informa a case-service."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from backend.shared import egress


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for var in ("TERO_ISOLATED_MODE", "TERO_EGRESS_ALLOW", "TERO_INTERNAL_DOMAINS", "TERO_EGRESS_DISABLED"):
        monkeypatch.delenv(var, raising=False)
    egress.reset_for_tests()
    egress._service_name = "prueba-service"
    egress._patch_httpx()
    yield
    egress.reset_for_tests()


@pytest.mark.parametrize("host,internal", [
    ("case-service", True), ("postgres", True), ("localhost", True), ("127.0.0.1", True), ("10.1.2.3", True),
    ("192.168.0.10", True), ("172.20.0.5", True), ("169.254.169.254", True), ("100.64.1.1", True), ("[::1]", True),
    ("tero.local", True), ("git.empresa.lan", True), ("db.internal", True), ("", True),
    ("api.abuseipdb.com", False), ("8.8.8.8", False), ("github.com", False), ("hooks.slack.com.", False),
])
def test_is_internal(host, internal):
    assert egress.is_internal(host) is internal


def test_custom_internal_domains(monkeypatch):
    assert egress.is_internal("git.miempresa.com.ar") is False
    monkeypatch.setenv("TERO_INTERNAL_DOMAINS", "miempresa.com.ar")
    assert egress.is_internal("git.miempresa.com.ar") is True


def test_guard_records_only_external_and_counts():
    egress.guard("case-service")
    egress.guard("10.0.0.5")
    egress.guard("API.AbuseIPDB.com", "http", "Reputacion de IP")
    egress.guard("api.abuseipdb.com", "http", "Reputacion de IP")
    rows = egress.pending()
    assert len(rows) == 1
    assert rows[0]["host"] == "api.abuseipdb.com" and rows[0]["count"] == 2 and rows[0]["blocked"] == 0
    assert rows[0]["purposes"] == ["Reputacion de IP"]


def test_isolated_mode_blocks_external_and_allows_internal(monkeypatch):
    monkeypatch.setenv("TERO_ISOLATED_MODE", "1")
    egress.guard("soar-service")  # interno: pasa
    with pytest.raises(egress.EgressBlocked) as exc:
        egress.guard("hooks.slack.com", "http", "Aviso")
    assert isinstance(exc.value, httpx.ConnectError) and exc.value.host == "hooks.slack.com"
    row = egress.pending()[0]
    assert row["host"] == "hooks.slack.com" and row["count"] == 1 and row["blocked"] == 1


def test_allowlist_allows_host_and_subdomains(monkeypatch):
    monkeypatch.setenv("TERO_ISOLATED_MODE", "true")
    monkeypatch.setenv("TERO_EGRESS_ALLOW", "smtp.empresa.com, espejo.cisa.gov")
    egress.guard("smtp.empresa.com", "smtp")
    egress.guard("a.espejo.cisa.gov")
    with pytest.raises(egress.EgressBlocked):
        egress.guard("otro.com")
    with pytest.raises(egress.EgressBlocked):
        egress.guard("malo-smtp.empresa.com.evil.io")
    blocked = {r["host"]: r["blocked"] for r in egress.pending()}
    assert blocked["smtp.empresa.com"] == 0 and blocked["otro.com"] == 1


def _client(calls):
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"ok": True})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_httpx_calls_are_audited_and_blocked_before_leaving(monkeypatch):
    calls = []

    async def main():
        async with _client(calls) as c:
            await c.get("http://case-service:8000/health")
            await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1")
            monkeypatch.setenv("TERO_ISOLATED_MODE", "1")
            with pytest.raises(httpx.ConnectError):
                await c.post("https://api.first.org/data/v1/epss", json={"secreto": "x"})
            await c.get("http://siem-service:8000/health")

    asyncio.run(main())
    assert calls == ["http://case-service:8000/health", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1",
                     "http://siem-service:8000/health"]  # la llamada bloqueada nunca llego al transporte
    by_host = {r["host"]: r for r in egress.pending()}
    assert set(by_host) == {"services.nvd.nist.gov", "api.first.org"}
    assert by_host["api.first.org"]["blocked"] == 1 and by_host["services.nvd.nist.gov"]["blocked"] == 0
    # solo el nombre de host: ni ruta ni parametros ni cuerpo
    assert "CVE-2024-1" not in str(egress.pending()) and "secreto" not in str(egress.pending())


def test_sync_client_is_audited_too():
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
        c.get("https://crt.sh/?q=ejemplo.com")
    assert egress.pending()[0]["host"] == "crt.sh"


def test_snapshot_resets_and_restore_merges():
    egress.guard("a.com")
    egress.guard("a.com")
    first = egress.snapshot_and_reset()
    assert egress.pending() == [] and first[0]["count"] == 2
    egress.guard("a.com", "http", "nuevo")
    egress._restore(first)
    row = egress.pending()[0]
    assert row["count"] == 3 and row["purposes"] == ["nuevo"]


def test_flush_failure_keeps_counts_and_success_clears(monkeypatch):
    egress.guard("b.com")
    monkeypatch.setattr(egress, "CASE_SERVICE_URL", "http://127.0.0.1:9")
    assert asyncio.run(egress.flush()) is False
    assert egress.pending()[0]["count"] == 1  # no se perdio

    sent = []
    real = httpx.AsyncClient

    def handler(request):
        import json
        sent.append(json.loads(request.content))
        return httpx.Response(204)

    monkeypatch.setattr(egress.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    assert asyncio.run(egress.flush()) is True
    assert sent[0]["service"] == "prueba-service" and sent[0]["destinations"][0]["host"] == "b.com"
    assert egress.pending() == []


def test_flush_can_be_disabled(monkeypatch):
    egress.guard("c.com")
    monkeypatch.setenv("TERO_EGRESS_DISABLED", "1")
    assert asyncio.run(egress.flush()) is True
    assert egress.pending()[0]["count"] == 1


def test_install_hooks_into_existing_lifespan(monkeypatch):
    from contextlib import asynccontextmanager
    from fastapi.testclient import TestClient

    events = []

    @asynccontextmanager
    async def lifespan(app):
        events.append("start")
        yield
        events.append("stop")

    app = FastAPI(lifespan=lifespan)
    monkeypatch.setattr(egress, "REPORT_INTERVAL_SECONDS", 3600)
    egress.install("prueba-service", app)
    egress.install("prueba-service", app)  # idempotente: no envuelve dos veces
    with TestClient(app):
        pass
    assert events == ["start", "stop"]
