"""Excepciones de riesgo: cuatro ojos, vencimiento que reabre, topes por severidad, aislamiento y prueba firmada."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app import exception_service as svc
from app import main
from app.assets import verificar_evidencia as ver
from app.exception_models import RiskException
from backend.shared import custody_core as core
from backend.shared.database import get_db
from backend.shared.security import create_access_token
from custody_helpers import file_db

A, B = "org-a", "org-b"
LONG = "Es un servidor heredado que no se puede parchear hasta la migracion de diciembre."
CTRL = "Segmentado en una VLAN aislada, acceso solo por VPN con MFA y monitoreo reforzado en el SIEM."


def tok(role="analyst", org=A, email="ana@acme.com"):
    return {"Authorization": "Bearer " + create_access_token(email, role, org_id=org, email=email)}


class FakeVulns:
    """Reemplaza al cliente de vuln-service: {(org, id): {...}} y un registro de llamadas."""

    def __init__(self):
        self.items = {}
        self.calls = []
        self.fail = False

    def add(self, vid, severity="high", status="open", org=A, title="Panel expuesto"):
        self.items[(org, vid)] = {"id": vid, "title": title, "severity": severity, "status": status, "cve_id": "CVE-2026-0001", "asset_id": ""}

    async def fetch(self, org_id, vuln_id):
        if self.fail:
            raise svc.ExceptionError("No pude consultar vuln-service. Proba de nuevo en un momento.", 502)
        v = self.items.get((org_id, vuln_id))
        if v is None:
            raise svc.ExceptionError("Vulnerabilidad no encontrada", 404)
        return dict(v)

    async def accept(self, org_id, vuln_id, action, note, actor):
        if self.fail:
            raise svc.ExceptionError("No pude comunicarme con vuln-service; no se cambio nada.", 502)
        v = self.items.get((org_id, vuln_id))
        if v is None:
            raise svc.ExceptionError("La vulnerabilidad ya no existe", 404)
        if action == "accept":
            if v["status"] not in ("open", "confirmed"):
                raise svc.ExceptionError("estado invalido", 409)
            v["status"] = "accepted_risk"
        else:
            if v["status"] != "accepted_risk":
                raise svc.ExceptionError("no hay riesgo aceptado", 409)
            v["status"] = "open"
        self.calls.append((action, vuln_id, actor))


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")
    monkeypatch.delenv("RISK_EXCEPTION_ALLOW_SELF_APPROVAL", raising=False)
    fake = FakeVulns()
    monkeypatch.setattr(svc, "fetch_vulnerability", fake.fetch)
    monkeypatch.setattr(svc, "set_acceptance", fake.accept)
    engine, Session = file_db()

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    holder = {"Session": Session}
    yield TestClient(main.app), fake, holder
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def req(client, vid="v1", days=60, controls=CTRL, justification=LONG, headers=None):
    return client.post("/risk-exceptions", headers=headers or tok(), json={
        "vuln_id": vid, "justification": justification, "compensating_controls": controls, "days": days})


def expire_in_db(holder, minutes_ago=5):
    async def run():
        async with holder["Session"]() as s:
            await s.execute(update(RiskException).values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)))
            await s.commit()
    asyncio.run(run())


def test_requires_login_and_role(env):
    client, fake, _ = env
    assert client.get("/risk-exceptions").status_code == 401
    assert client.get("/risk-exceptions", headers=tok("viewer")).status_code == 403
    fake.add("v1")
    assert req(client, headers=tok("viewer")).status_code == 403
    assert client.post("/risk-exceptions/x/approve", headers=tok("analyst"), json={"note": "x" * 12}).status_code == 403


def test_request_validations(env):
    client, fake, _ = env
    fake.add("v1", "high")
    fake.add("v-crit", "critical")
    fake.add("v-med", "medium")
    fake.add("v-done", "high", status="remediated")
    assert req(client, "inexistente").status_code == 404
    assert req(client, "v-done").status_code == 409
    assert req(client, justification="corta").status_code == 422
    assert req(client, controls="").status_code == 422  # alta: controles obligatorios
    assert req(client, controls="poco").status_code == 422
    assert req(client, days=3).status_code == 422
    assert req(client, days=181).status_code == 422  # alta: tope 180
    assert req(client, "v-crit", days=91).status_code == 422  # critica: tope 90
    ok_med = req(client, "v-med", days=365, controls="")  # media: sin controles obligatorios, hasta 365
    assert ok_med.status_code == 201
    assert req(client, "v1", days=180).status_code == 201
    assert req(client, "v1").status_code == 409  # ya tiene una pendiente


def test_vuln_service_down_blocks_the_request_with_502(env):
    client, fake, _ = env
    fake.add("v1")
    fake.fail = True
    r = req(client)
    assert r.status_code == 502 and "vuln-service" in r.json()["detail"]
    assert client.get("/risk-exceptions", headers=tok()).json() == []


def test_four_eyes_the_requester_cannot_approve(env):
    client, fake, _ = env
    fake.add("v1")
    eid = req(client, headers=tok("soc_manager", email="sofia@acme.com")).json()["id"]
    r = client.post(f"/risk-exceptions/{eid}/approve", headers=tok("soc_manager", email="sofia@acme.com"), json={"note": "Apruebo porque si, ok"})
    assert r.status_code == 403 and "otra persona" in r.json()["detail"]
    assert fake.items[(A, "v1")]["status"] == "open"


def test_self_approval_can_be_enabled_and_is_recorded(env, monkeypatch):
    client, fake, _ = env
    monkeypatch.setenv("RISK_EXCEPTION_ALLOW_SELF_APPROVAL", "true")
    fake.add("v1")
    h = tok("admin", email="solo@acme.com")
    eid = req(client, headers=h).json()["id"]
    assert client.post(f"/risk-exceptions/{eid}/approve", headers=h, json={"note": "Unica persona de la empresa"}).status_code == 200
    ev = client.get("/custody/entries?limit=50&event_type=risk_exception.approved", headers=h).json()["items"]
    assert ev[0]["payload"]["self_approved"] is True


def test_critical_needs_an_admin(env):
    client, fake, _ = env
    fake.add("vc", "critical")
    eid = req(client, "vc", days=30).json()["id"]
    r = client.post(f"/risk-exceptions/{eid}/approve", headers=tok("soc_manager", email="sofia@acme.com"), json={"note": "Lo apruebo yo, manager"})
    assert r.status_code == 403 and "administrador" in r.json()["detail"]
    r = client.post(f"/risk-exceptions/{eid}/reject", headers=tok("soc_manager", email="sofia@acme.com"), json={"note": "No se aprueba, manager"})
    assert r.status_code == 403
    ok = client.post(f"/risk-exceptions/{eid}/approve", headers=tok("admin", email="root@acme.com"), json={"note": "Aprobada con controles revisados"})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"


def test_approval_accepts_the_vulnerability_and_sets_expiry(env):
    client, fake, _ = env
    fake.add("v1")
    eid = req(client, days=45).json()["id"]
    r = client.post(f"/risk-exceptions/{eid}/approve", headers=tok("soc_manager", email="sofia@acme.com"), json={"note": "Controles compensatorios revisados"})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "approved" and d["decided_by"] == "sofia@acme.com" and 44 <= d["days_left"] <= 45
    assert fake.items[(A, "v1")]["status"] == "accepted_risk"
    assert fake.calls == [("accept", "v1", "sofia@acme.com")]
    again = client.post(f"/risk-exceptions/{eid}/approve", headers=tok("admin", email="root@acme.com"), json={"note": "Otra vez, para probar"})
    assert again.status_code == 409


def test_approval_needs_a_reason_and_rolls_back_if_vuln_service_fails(env):
    client, fake, _ = env
    fake.add("v1")
    eid = req(client).json()["id"]
    h = tok("soc_manager", email="sofia@acme.com")
    assert client.post(f"/risk-exceptions/{eid}/approve", headers=h, json={"note": "ok"}).status_code == 422
    fake.fail = True
    r = client.post(f"/risk-exceptions/{eid}/approve", headers=h, json={"note": "Controles compensatorios revisados"})
    assert r.status_code == 502
    fake.fail = False
    assert client.get(f"/risk-exceptions/{eid}", headers=h).json()["status"] == "pending"


def test_reject_and_withdraw(env):
    client, fake, _ = env
    fake.add("v1")
    fake.add("v2")
    e1 = req(client, "v1").json()["id"]
    boss = tok("soc_manager", email="sofia@acme.com")
    assert client.post(f"/risk-exceptions/{e1}/reject", headers=boss, json={"note": "no"}).status_code == 422
    r = client.post(f"/risk-exceptions/{e1}/reject", headers=boss, json={"note": "El parche existe: aplicalo esta semana"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert fake.items[(A, "v1")]["status"] == "open"
    e2 = req(client, "v2").json()["id"]
    assert client.post(f"/risk-exceptions/{e2}/withdraw", headers=tok(email="otro@acme.com")).status_code == 403
    assert client.post(f"/risk-exceptions/{e2}/withdraw", headers=tok()).json()["status"] == "withdrawn"
    assert client.post(f"/risk-exceptions/{e2}/withdraw", headers=tok()).status_code == 409
    assert req(client, "v1").status_code == 201  # tras rechazar se puede volver a pedir


def test_revoke_reopens_the_vulnerability(env):
    client, fake, _ = env
    fake.add("v1")
    eid = req(client).json()["id"]
    boss = tok("soc_manager", email="sofia@acme.com")
    assert client.post(f"/risk-exceptions/{eid}/revoke", headers=boss, json={"note": "todavia no esta aprobada"}).status_code == 409
    client.post(f"/risk-exceptions/{eid}/approve", headers=boss, json={"note": "Controles compensatorios revisados"})
    assert client.post(f"/risk-exceptions/{eid}/revoke", headers=tok("analyst"), json={"note": "x" * 12}).status_code == 403
    r = client.post(f"/risk-exceptions/{eid}/revoke", headers=boss, json={"note": "Aparecio un exploit publico"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    assert fake.items[(A, "v1")]["status"] == "open"


def test_expiry_reopens_the_vulnerability_and_lists_it_as_expired(env):
    client, fake, holder = env
    fake.add("v1")
    eid = req(client).json()["id"]
    client.post(f"/risk-exceptions/{eid}/approve", headers=tok("soc_manager", email="sofia@acme.com"), json={"note": "Controles compensatorios revisados"})
    assert fake.items[(A, "v1")]["status"] == "accepted_risk"
    expire_in_db(holder)
    lst = client.get("/risk-exceptions", headers=tok()).json()  # el listado vence lo que corresponda
    assert lst[0]["status"] == "expired" and "Vencio" in lst[0]["end_reason"]
    assert fake.items[(A, "v1")]["status"] == "open"
    assert ("reopen", "v1", "sistema") in fake.calls
    kinds = [e["event_type"] for e in client.get("/custody/entries?limit=50", headers=tok()).json()["items"]]
    assert "risk_exception.expired" in kinds


def test_expiry_when_vuln_service_is_down_keeps_it_active_and_retries(env):
    client, fake, holder = env
    fake.add("v1")
    eid = req(client).json()["id"]
    client.post(f"/risk-exceptions/{eid}/approve", headers=tok("soc_manager", email="sofia@acme.com"), json={"note": "Controles compensatorios revisados"})
    expire_in_db(holder)
    fake.fail = True
    assert client.get("/risk-exceptions", headers=tok()).json()[0]["status"] == "approved"
    fake.fail = False
    assert client.get("/risk-exceptions", headers=tok()).json()[0]["status"] == "expired"


def test_expiry_when_vuln_already_changed_state_closes_quietly(env):
    client, fake, holder = env
    fake.add("v1")
    eid = req(client).json()["id"]
    client.post(f"/risk-exceptions/{eid}/approve", headers=tok("soc_manager", email="sofia@acme.com"), json={"note": "Controles compensatorios revisados"})
    fake.items[(A, "v1")]["status"] = "remediated"
    expire_in_db(holder)
    r = client.get("/risk-exceptions", headers=tok()).json()[0]
    assert r["status"] == "expired" and "ya no estaba" in r["end_reason"]
    assert fake.items[(A, "v1")]["status"] == "remediated"  # no se reabre algo ya corregido


def test_summary_counts(env):
    client, fake, _ = env
    for i in range(3):
        fake.add(f"v{i}")
    ids = [req(client, f"v{i}", days=10 if i == 0 else 60).json()["id"] for i in range(3)]
    boss = tok("soc_manager", email="sofia@acme.com")
    client.post(f"/risk-exceptions/{ids[0]}/approve", headers=boss, json={"note": "Controles compensatorios revisados"})
    client.post(f"/risk-exceptions/{ids[1]}/approve", headers=boss, json={"note": "Controles compensatorios revisados"})
    s = client.get("/risk-exceptions/summary", headers=tok()).json()
    assert s["pending"] == 1 and s["active"] == 2 and s["expiring_soon"] == 1 and s["active_critical_or_high"] == 2 and s["total"] == 3


def test_organizations_are_isolated(env):
    client, fake, _ = env
    fake.add("v1")
    eid = req(client).json()["id"]
    other = tok("admin", org=B, email="root@otra.com")
    assert client.get(f"/risk-exceptions/{eid}", headers=other).status_code == 404
    assert client.get("/risk-exceptions", headers=other).json() == []
    assert client.post(f"/risk-exceptions/{eid}/approve", headers=other, json={"note": "Intento ajeno aprobado"}).status_code == 404
    assert req(client, "v1", headers=other).status_code == 404  # esa vulnerabilidad no es de la otra org


def test_chain_events_and_signed_attestation(env):
    client, fake, _ = env
    fake.add("v1", "critical")
    eid = req(client, "v1", days=30).json()["id"]
    assert client.get(f"/risk-exceptions/{eid}/attestation", headers=tok()).status_code == 404  # sin decision todavia
    client.post(f"/risk-exceptions/{eid}/approve", headers=tok("admin", email="root@acme.com"), json={"note": "Aprobada con controles revisados"})
    r = client.get(f"/risk-exceptions/{eid}/attestation", headers=tok())
    assert r.status_code == 200
    doc = r.json()
    assert doc["kind"] == "risk_exception" and doc["body"]["exception"]["decided_by"] == "root@acme.com"
    assert [h["event_type"] for h in doc["body"]["history"]] == ["risk_exception.requested", "risk_exception.approved"]
    assert doc["body"]["chain_ok_at_signing"] is True
    assert core.verify_attestation(doc)["ok"] and ver.verify_attestation(doc)["ok"]
    doc["body"]["exception"]["decided_by"] = "otro@acme.com"
    assert not ver.verify_attestation(doc)["ok"]
    assert client.get("/custody/verify", headers=tok()).json()["ok"] is True


def test_register_csv_neutralizes_formulas(env):
    client, fake, _ = env
    fake.add("v1", title="=CMD|' /C calc'!A0")
    req(client)
    body = client.get("/risk-exceptions/register.csv", headers=tok()).content.decode("utf-8-sig")
    assert "'=CMD" in body and "\n=CMD" not in body
