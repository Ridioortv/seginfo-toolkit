"""Regression tests para POST /vulnerabilities/ingest -- antes de este fix
no exigia NINGUN JWT y confiaba en un "organization_id" que mandaba el
propio body del caller: cualquiera que llegara al puerto publicado de
vuln-service (ver docker-compose.yml) podia inyectar hallazgos falsos en
CUALQUIER organizacion sin autenticarse. Ahora exige un JWT valido (el
mismo mecanismo que ya usa get_current_claims para /vulnerabilities y
companeros) y el organization_id SIEMPRE sale del claim org_id de ese
JWT, nunca del body -- ver app/services.py::ingest_findings y
scan-service/app/services.py::_forward_findings_to_vuln_service (que
ahora manda un JWT de servicio-a-servicio en vez del organization_id en
el payload).

Sin DB real (se monkeypatchea services.ingest_findings, igual de aislado
que los demas tests de este servicio, que evitan Postgres por completo) y
sin JWT real (se overridea get_current_claims con dependency_overrides,
salvo en el test que prueba justamente la falta de token)."""
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


def test_ingest_without_any_token_is_rejected(client):
    # Sin override de get_current_claims -- el flujo real: sin header
    # Authorization, oauth2_scheme devuelve None y get_current_claims
    # levanta 401 antes de llegar a tocar la DB o a services.ingest_findings.
    r = client.post("/vulnerabilities/ingest", json={"findings": [{"title": "x"}]})
    assert r.status_code == 401


def test_ingest_uses_organization_id_from_jwt_claims_not_from_body(client, monkeypatch):
    captured = {}

    async def fake_ingest_findings(db, payload, organization_id):
        captured["organization_id"] = organization_id
        captured["payload"] = payload
        return 1, 0

    monkeypatch.setattr(svc, "ingest_findings", fake_ingest_findings)
    m.app.dependency_overrides[m.get_current_claims] = lambda: {
        "sub": "system:scan-service", "role": "admin", "org_id": "org-real", "type": "access",
    }
    m.app.dependency_overrides[m.get_db] = _fake_get_db

    # Un body que intenta forjar un organization_id distinto del JWT --
    # IngestRequest ya no tiene ese campo (ver app/schemas.py), asi que
    # Pydantic simplemente lo ignora: no puede pisar el org_id real.
    r = client.post(
        "/vulnerabilities/ingest",
        json={"findings": [{"title": "hallazgo"}], "organization_id": "org-evil"},
    )
    assert r.status_code == 201
    assert captured["organization_id"] == "org-real"
