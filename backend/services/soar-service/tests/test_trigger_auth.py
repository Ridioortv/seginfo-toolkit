"""Regression test para POST /trigger -- antes no exigia ningun JWT y
confiaba en el organization_id que mandaba el propio body del caller:
cualquiera que alcanzara el puerto publicado de soar-service (ver
docker-compose.yml) podia disparar los playbooks de respuesta automatica
(bloqueo de IP, aislamiento de host, ticket, notificacion) de CUALQUIER
organizacion sin autenticarse. Ahora exige un JWT (el mismo mecanismo que
get_current_claims usa para /playbooks y companeros, incluyendo el JWT de
servicio-a-servicio que siem-service manda ahora, ver
siem-service/app/services.py::_notify_soar) y el organization_id SIEMPRE
sale del claim org_id de ese JWT, nunca del body.

Sin DB real (se monkeypatchea services.trigger_playbooks) y sin JWT real
(se overridea get_current_claims con dependency_overrides, salvo en el
test que prueba justamente la falta de token) -- mismo patron que
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


def test_trigger_without_any_token_is_rejected(client):
    r = client.post("/trigger", json={"alert_id": "a1", "severity": "high"})
    assert r.status_code == 401


def test_trigger_uses_organization_id_from_jwt_claims_not_from_body(client, monkeypatch):
    captured = {}

    async def fake_trigger_playbooks(db, payload):
        captured["organization_id"] = payload.organization_id
        return 0, []

    monkeypatch.setattr(svc, "trigger_playbooks", fake_trigger_playbooks)
    m.app.dependency_overrides[m.get_current_claims] = lambda: {
        "sub": "system:siem-service", "role": "admin", "org_id": "org-real", "type": "access",
    }
    m.app.dependency_overrides[m.get_db] = _fake_get_db

    r = client.post(
        "/trigger",
        json={"alert_id": "a1", "severity": "high", "organization_id": "org-evil"},
    )
    assert r.status_code == 200
    assert captured["organization_id"] == "org-real"
