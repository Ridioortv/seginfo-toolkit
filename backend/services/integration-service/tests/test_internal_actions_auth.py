"""Regression tests para POST /internal/actions/{block-ip,isolate-host,
create-ticket} -- antes ninguno exigia JWT y confiaban en el
organization_id que mandaba el propio body del caller: cualquiera que
alcanzara el puerto publicado de integration-service (ver
docker-compose.yml) podia disparar un bloqueo/aislamiento/ticket real
contra el conector de CUALQUIER organizacion. Ahora exigen el mismo JWT de
servicio-a-servicio que soar-service manda desde app/actions/base.py
(service_auth_headers) y el organization_id SIEMPRE sale del claim org_id
de ese JWT, nunca del body -- mismo patron que
vuln-service/tests/test_ingest_auth.py."""
import pytest
from fastapi.testclient import TestClient

import app.main as m
import app.services as svc


class _FakeDbSession:
    async def commit(self):
        pass


async def _fake_get_db():
    yield _FakeDbSession()


@pytest.fixture
def client():
    yield TestClient(m.app)
    m.app.dependency_overrides.pop(m.get_current_claims, None)
    m.app.dependency_overrides.pop(m.get_db, None)


def _authed(client):
    m.app.dependency_overrides[m.get_current_claims] = lambda: {
        "sub": "system:soar-service", "role": "admin", "org_id": "org-real", "type": "access",
    }
    m.app.dependency_overrides[m.get_db] = _fake_get_db


class TestBlockIpAuth:
    def test_rejected_without_token(self, client):
        r = client.post("/internal/actions/block-ip", json={"ip": "1.2.3.4"})
        assert r.status_code == 401

    def test_organization_id_comes_from_jwt_not_body(self, client, monkeypatch):
        captured = {}

        async def fake_block_ip(db, ip, organization_id, connector_id=None):
            captured["organization_id"] = organization_id
            import types
            return types.SimpleNamespace(id="log-1", status="simulated", target=ip, connector_id=connector_id or "", organization_id=organization_id, action="block_ip", error="", created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))

        monkeypatch.setattr(svc, "block_ip", fake_block_ip)
        _authed(client)
        r = client.post("/internal/actions/block-ip", json={"ip": "1.2.3.4", "organization_id": "org-evil"})
        assert r.status_code == 200
        assert captured["organization_id"] == "org-real"


class TestIsolateHostAuth:
    def test_rejected_without_token(self, client):
        r = client.post("/internal/actions/isolate-host", json={"hostname": "host1"})
        assert r.status_code == 401

    def test_organization_id_comes_from_jwt_not_body(self, client, monkeypatch):
        captured = {}

        async def fake_isolate_host(db, hostname, organization_id, connector_id=None):
            captured["organization_id"] = organization_id
            import types
            return types.SimpleNamespace(id="log-1", status="simulated", target=hostname, connector_id=connector_id or "", organization_id=organization_id, action="isolate_host", error="", created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))

        monkeypatch.setattr(svc, "isolate_host", fake_isolate_host)
        _authed(client)
        r = client.post("/internal/actions/isolate-host", json={"hostname": "host1", "organization_id": "org-evil"})
        assert r.status_code == 200
        assert captured["organization_id"] == "org-real"


class TestCreateTicketAuth:
    def test_rejected_without_token(self, client):
        r = client.post("/internal/actions/create-ticket", json={"title": "t", "description": "d"})
        assert r.status_code == 401

    def test_organization_id_comes_from_jwt_not_body(self, client, monkeypatch):
        captured = {}

        async def fake_create_ticket(db, title, description, priority, connector_id, organization_id):
            captured["organization_id"] = organization_id
            import types
            return types.SimpleNamespace(id="log-1", status="simulated", title=title, priority=priority or "", external_key="", external_url="", connector_id=connector_id or "", organization_id=organization_id, error="", created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))

        monkeypatch.setattr(svc, "create_ticket", fake_create_ticket)
        _authed(client)
        r = client.post(
            "/internal/actions/create-ticket",
            json={"title": "t", "description": "d", "organization_id": "org-evil"},
        )
        assert r.status_code == 200
        assert captured["organization_id"] == "org-real"
