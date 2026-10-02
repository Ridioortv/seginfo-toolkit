"""Regression test para POST /internal/notify -- antes no exigia ningun JWT
y confiaba en el organization_id que mandaba el propio body del caller:
cualquiera que alcanzara el puerto publicado de notification-service (ver
docker-compose.yml) podia disparar una notificacion real por el canal
configurado de CUALQUIER organizacion. Ahora exige el mismo JWT de
servicio-a-servicio que soar-service manda desde
app/actions/base.py::service_auth_headers y el organization_id SIEMPRE
sale del claim org_id de ese JWT, nunca del body -- mismo patron que
vuln-service/tests/test_ingest_auth.py."""
import datetime

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


def test_internal_notify_rejected_without_token(client):
    r = client.post("/internal/notify", json={"subject": "s", "body": "b"})
    assert r.status_code == 401


def test_internal_notify_organization_id_comes_from_jwt_not_body(client, monkeypatch):
    captured = {}

    async def fake_notify(db, payload):
        captured["organization_id"] = payload.organization_id
        return []

    monkeypatch.setattr(svc, "notify", fake_notify)
    m.app.dependency_overrides[m.get_current_claims] = lambda: {
        "sub": "system:soar-service", "role": "admin", "org_id": "org-real", "type": "access",
    }
    m.app.dependency_overrides[m.get_db] = _fake_get_db

    r = client.post(
        "/internal/notify",
        json={"subject": "s", "body": "b", "organization_id": "org-evil"},
    )
    assert r.status_code == 200
    assert captured["organization_id"] == "org-real"
