"""Aceptar el riesgo de una vulnerabilidad alta/critica exige una excepcion aprobada (case-service): el triage directo
se rechaza y solo el servicio de excepciones puede aceptarla y reabrirla."""
import asyncio
import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import main
from app.models import Base, Vulnerability, VulnSeverity, VulnStatus
from backend.shared.database import get_db
from backend.shared.security import create_access_token


def user(role="analyst", org="o1"):
    return {"Authorization": "Bearer " + create_access_token("u1", role, org_id=org)}


def service(org="o1"):
    return {"Authorization": "Bearer " + create_access_token("system:case-service", "admin", org_id=org)}


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("TERO_CUSTODY_DISABLED", "1")
    monkeypatch.delenv("VULN_ACCEPT_RISK_REQUIRES_EXCEPTION", raising=False)
    path = os.path.join(tempfile.mkdtemp(prefix="vuln-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as s:
            rows = {
                "crit": Vulnerability(organization_id="o1", title="Critica", severity=VulnSeverity.critical),
                "high": Vulnerability(organization_id="o1", title="Alta", severity=VulnSeverity.high),
                "med": Vulnerability(organization_id="o1", title="Media", severity=VulnSeverity.medium),
                "other": Vulnerability(organization_id="o2", title="Otra org", severity=VulnSeverity.high),
                "done": Vulnerability(organization_id="o1", title="Hecha", severity=VulnSeverity.high, status=VulnStatus.remediated),
            }
            s.add_all(rows.values())
            await s.commit()
            return {k: v.id for k, v in rows.items()}

    ids = asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app), ids
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def status_of(client, vid, org="o1"):
    return client.get(f"/vulnerabilities/{vid}", headers=user(org=org)).json()["status"]


def test_direct_accept_of_critical_or_high_is_rejected(env):
    client, ids = env
    for k in ("crit", "high"):
        r = client.patch(f"/vulnerabilities/{ids[k]}/triage", headers=user("admin"), json={"status": "accepted_risk", "note": "x"})
        assert r.status_code == 409 and "excepcion" in r.json()["detail"]
        assert status_of(client, ids[k]) == "open"


def test_medium_can_still_be_accepted_directly(env):
    client, ids = env
    r = client.patch(f"/vulnerabilities/{ids['med']}/triage", headers=user(), json={"status": "accepted_risk", "note": "ok"})
    assert r.status_code == 200 and r.json()["status"] == "accepted_risk"


def test_other_triage_states_are_unaffected(env):
    client, ids = env
    for st in ("confirmed", "false_positive", "remediated"):
        r = client.patch(f"/vulnerabilities/{ids['crit']}/triage", headers=user(), json={"status": st})
        assert r.status_code == 200, (st, r.text)


def test_the_check_can_be_disabled_for_single_person_installs(env, monkeypatch):
    client, ids = env
    monkeypatch.setenv("VULN_ACCEPT_RISK_REQUIRES_EXCEPTION", "false")
    r = client.patch(f"/vulnerabilities/{ids['crit']}/triage", headers=user(), json={"status": "accepted_risk"})
    assert r.status_code == 200


def test_internal_endpoints_require_a_service_token(env):
    client, ids = env
    path = f"/internal/vulnerabilities/{ids['crit']}/risk-acceptance"
    assert client.post(path, json={"action": "accept"}).status_code == 401
    assert client.post(path, headers=user("admin"), json={"action": "accept"}).status_code == 403
    assert client.get(f"/internal/vulnerabilities/{ids['crit']}", headers=user("admin")).status_code == 403


def test_service_can_accept_then_reopen(env):
    client, ids = env
    path = f"/internal/vulnerabilities/{ids['crit']}/risk-acceptance"
    r = client.post(path, headers=service(), json={"action": "accept", "note": "Excepcion e-1 hasta 2027-01-01", "actor": "ana@acme.com"})
    assert r.status_code == 200 and r.json()["status"] == "accepted_risk"
    again = client.post(path, headers=service(), json={"action": "accept"})
    assert again.status_code == 409
    r2 = client.post(path, headers=service(), json={"action": "reopen", "note": "La excepcion vencio"})
    assert r2.status_code == 200 and r2.json()["status"] == "open"
    assert client.post(path, headers=service(), json={"action": "reopen"}).status_code == 409


def test_internal_cannot_touch_closed_or_foreign_vulnerabilities(env):
    client, ids = env
    assert client.post(f"/internal/vulnerabilities/{ids['done']}/risk-acceptance", headers=service(), json={"action": "accept"}).status_code == 409
    assert client.post(f"/internal/vulnerabilities/{ids['other']}/risk-acceptance", headers=service(), json={"action": "accept"}).status_code == 404
    assert client.get(f"/internal/vulnerabilities/{ids['other']}", headers=service()).status_code == 404
    got = client.get(f"/internal/vulnerabilities/{ids['crit']}", headers=service()).json()
    assert got["severity"] == "critical" and got["status"] == "open"


def test_invalid_action_is_422(env):
    client, ids = env
    assert client.post(f"/internal/vulnerabilities/{ids['crit']}/risk-acceptance", headers=service(), json={"action": "borrar"}).status_code == 422


# ---- ticket externo resuelto (integration-service) ----

def test_internal_ticket_resolved_marks_remediated_and_starts_closure(env):
    client, ids = env
    body = {"ticket_key": "SEC-12", "provider": "jira", "note": "Parcheado por infraestructura"}
    r = client.post(f"/internal/vulnerabilities/{ids['high']}/ticket-resolved", headers=service(), json=body)
    assert r.status_code == 200 and r.json()["changed"] is True and r.json()["status"] == "remediated"
    v = client.get(f"/internal/vulnerabilities/{ids['high']}", headers=service()).json()
    assert v["status"] == "remediated" and v["fixed_version"] == "" and "remediation_steps" in v and "description" in v
    # la verificacion con un nuevo escaneo queda en marcha (o sin soporte), nunca se da por "verificada" sola
    assert client.get(f"/vulnerabilities/{ids['high']}", headers=user()).json()["closure_status"] != "verified"
    # repetir el aviso no cambia nada
    again = client.post(f"/internal/vulnerabilities/{ids['high']}/ticket-resolved", headers=service(), json=body)
    assert again.json() == {"id": ids["high"], "status": "remediated", "changed": False}


def test_ticket_resolved_does_not_touch_accepted_or_other_org_and_requires_service_token(env):
    client, ids = env
    body = {"ticket_key": "SEC-1", "provider": "jira"}
    client.post(f"/internal/vulnerabilities/{ids['med']}/risk-acceptance", headers=service(), json={"action": "accept"})
    r = client.post(f"/internal/vulnerabilities/{ids['med']}/ticket-resolved", headers=service(), json=body)
    assert r.json()["changed"] is False and r.json()["status"] == "accepted_risk"
    assert client.post(f"/internal/vulnerabilities/{ids['other']}/ticket-resolved", headers=service(), json=body).status_code == 404
    assert client.post(f"/internal/vulnerabilities/{ids['crit']}/ticket-resolved", headers=user("admin"), json=body).status_code == 403
    assert client.post(f"/internal/vulnerabilities/{ids['crit']}/ticket-resolved", json=body).status_code == 401
    assert client.post(f"/internal/vulnerabilities/{ids['crit']}/ticket-resolved", headers=service(), json={}).status_code == 422
