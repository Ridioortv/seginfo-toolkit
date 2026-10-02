"""Regression tests para _forward_findings_to_vuln_service /
_forward_agent_findings_to_vuln_service -- antes mandaban un
"organization_id" suelto en el body de POST /vulnerabilities/ingest, SIN
ningun JWT que lo respaldara (ver app/services.py). Como ese endpoint no
exigia autenticacion, cualquiera que llegara al puerto publicado de
vuln-service (ver docker-compose.yml) podia inyectar hallazgos falsos en
CUALQUIER organizacion con solo adivinar/conocer su organization_id.

Ahora mandan un JWT de servicio-a-servicio de corta vida (mismo patron que
ya usa vuln-service para llamar a asset-service, ver
vuln-service/app/services.py::_get_asset_criticality) con el org_id REAL
del job, y el body ya no lleva organization_id en absoluto -- vuln-service
deriva la organizacion del JWT (org_id_from_claims), nunca del body (ver
vuln-service/app/main.py::ingest / app/services.py::ingest_findings)."""
import asyncio
from types import SimpleNamespace

import pytest

import app.services as services
from backend.shared.security import decode_token


class _FakeResponse:
    def raise_for_status(self):
        pass


class _FakeAsyncClient:
    """Dobla a httpx.AsyncClient lo justo para capturar la llamada real
    que hace _forward_*_to_vuln_service -- igual de aislado que el resto
    de los tests de este archivo (sin red real, sin vuln-service real)."""

    captured: dict = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def post(self, url, json=None, headers=None):
        _FakeAsyncClient.captured = {"url": url, "json": json, "headers": headers}
        return _FakeResponse()


@pytest.fixture
def fake_httpx(monkeypatch):
    _FakeAsyncClient.captured = {}
    monkeypatch.setattr(services.httpx, "AsyncClient", _FakeAsyncClient)
    return _FakeAsyncClient


def _assert_valid_service_token_for_org(headers, organization_id):
    auth = headers["Authorization"]
    assert auth.startswith("Bearer ")
    claims = decode_token(auth.removeprefix("Bearer "))
    assert claims["type"] == "access"
    assert claims["org_id"] == organization_id
    assert claims["sub"] == "system:scan-service"


def test_forward_findings_sends_service_jwt_not_raw_org_id(fake_httpx):
    job = SimpleNamespace(
        id="job-1", asset_id="asset-1", scanner_type=SimpleNamespace(value="nmap"),
        findings=[{"title": "x"}], organization_id="org-real",
    )
    asyncio.run(services._forward_findings_to_vuln_service(job))

    captured = _FakeAsyncClient.captured
    assert "organization_id" not in captured["json"]
    _assert_valid_service_token_for_org(captured["headers"], "org-real")


def test_forward_agent_findings_sends_service_jwt_not_raw_org_id(fake_httpx):
    job = SimpleNamespace(
        id="job-2", scanner_type="nmap", findings=[{"title": "y"}], organization_id="org-real-2",
    )
    asyncio.run(services._forward_agent_findings_to_vuln_service(job))

    captured = _FakeAsyncClient.captured
    assert "organization_id" not in captured["json"]
    _assert_valid_service_token_for_org(captured["headers"], "org-real-2")
