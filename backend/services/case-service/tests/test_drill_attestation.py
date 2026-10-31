"""Prueba firmada de un simulacro: se arma desde la cadena de custodia y se verifica sin TERO."""
import asyncio

import pytest
from fastapi.testclient import TestClient

from app import main
from app.assets import verificar_evidencia as ver
from backend.shared import custody_core as core
from backend.shared.database import get_db
from backend.shared.security import create_access_token
from custody_helpers import file_db

A, B = "org-a", "org-b"


def tok(role="analyst", org=A):
    return {"Authorization": "Bearer " + create_access_token("u1", role, org_id=org, email="ana@acme.com")}


def svc(org=A):
    return {"Authorization": "Bearer " + create_access_token("system:purple-service", "admin", org_id=org)}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")
    engine, Session = file_db()

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def post(client, event_type, drill="d-1", org=A, **payload):
    r = client.post("/internal/custody/events", headers=svc(org), json={
        "event_type": event_type, "source": "purple-service", "subject_type": "drill", "subject_id": drill,
        "refs": [f"drill:{drill}"], "payload": {"scenario": "phishing", **payload}})
    assert r.status_code == 201, r.text


def test_roles_and_not_finished(client):
    assert client.get("/drills/d-1/attestation").status_code == 401
    assert client.get("/drills/d-1/attestation", headers=tok("viewer")).status_code == 403
    post(client, "drill.started")
    assert client.get("/drills/d-1/attestation", headers=tok()).status_code == 404


def test_signed_attestation_verifies_and_detects_tampering(client):
    post(client, "drill.started")
    post(client, "drill.completed", status="completed", score=85, ack_seconds=420.0, close_seconds=3000.0, rating="preparado")
    post(client, "drill.started", drill="otro")
    r = client.get("/drills/d-1/attestation", headers=tok())
    assert r.status_code == 200 and "prueba-simulacro-d-1" in r.headers["content-disposition"]
    doc = r.json()
    assert doc["kind"] == "drill" and doc["body"]["status"] == "completed" and doc["body"]["result"]["score"] == 85
    assert [h["event_type"] for h in doc["body"]["history"]] == ["drill.started", "drill.completed"]
    assert doc["body"]["chain_ok_at_signing"] is True and "No ejecuto ninguna tecnica" in doc["body"]["meaning"]
    assert core.verify_attestation(doc)["ok"] and ver.verify_attestation(doc)["ok"]
    doc["body"]["result"]["score"] = 100
    assert not core.verify_attestation(doc)["ok"] and not ver.verify_attestation(doc)["ok"]


def test_other_org_gets_404(client):
    post(client, "drill.completed", status="completed", score=50)
    assert client.get("/drills/d-1/attestation", headers=tok(org=B)).status_code == 404
