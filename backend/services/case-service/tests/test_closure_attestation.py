"""Prueba firmada del cierre verificado: se arma desde la cadena de custodia y se verifica sin TERO."""
import asyncio
import json

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
    return {"Authorization": "Bearer " + create_access_token("system:vuln-service", "admin", org_id=org)}


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


def post(client, event_type, vuln="v-1", org=A, **payload):
    r = client.post("/internal/custody/events", headers=svc(org), json={
        "event_type": event_type, "source": "vuln-service", "subject_type": "vuln", "subject_id": vuln,
        "refs": [f"vuln:{vuln}", "scan:job-9"], "payload": {"title": "Panel expuesto", "closure_scan_job_id": "job-9", **payload}})
    assert r.status_code == 201, r.text


def test_requires_login_and_role(client):
    assert client.get("/closure/v-1/attestation").status_code == 401
    assert client.get("/closure/v-1/attestation", headers=tok("viewer")).status_code == 403


def test_no_closure_yet_is_404(client):
    post(client, "vuln.status_changed", **{"from": "open", "to": "remediated"})
    assert client.get("/closure/v-1/attestation", headers=tok()).status_code == 404
    assert client.get("/closure/otra/attestation", headers=tok()).status_code == 404


def test_verified_attestation_is_signed_and_checkable(client, tmp_path):
    post(client, "vuln.status_changed", **{"from": "open", "to": "remediated"})
    post(client, "vuln.closure_requested")
    post(client, "vuln.closure_verified", mttr_real_hours=26.5, scan_total_findings=0)
    post(client, "vuln.status_changed", vuln="otra-vuln", **{"from": "open", "to": "confirmed"})
    r = client.get("/closure/v-1/attestation", headers=tok())
    assert r.status_code == 200 and "prueba-cierre-v-1" in r.headers["content-disposition"]
    doc = r.json()
    assert doc["kind"] == "closure" and doc["body"]["result"] == "verified"
    assert doc["body"]["evidence"]["mttr_real_hours"] == 26.5 and doc["body"]["chain_ok_at_signing"] is True
    assert [h["event_type"] for h in doc["body"]["history"]] == ["vuln.status_changed", "vuln.closure_requested", "vuln.closure_verified"]
    assert doc["body"]["custody_entry"]["seq"] == 3
    assert core.verify_attestation(doc)["ok"] and ver.verify_attestation(doc)["ok"]
    # cambiar el resultado invalida la firma
    doc["body"]["result"] = "failed"
    assert not core.verify_attestation(doc)["ok"] and not ver.verify_attestation(doc)["ok"]


def test_failed_attestation_and_most_recent_result_wins(client):
    post(client, "vuln.closure_verified")
    post(client, "vuln.closure_failed", matches=1)
    doc = client.get("/closure/v-1/attestation", headers=tok()).json()
    assert doc["body"]["result"] == "failed" and "volvio a detectar" in doc["body"]["meaning"]


def test_other_organization_cannot_get_it(client):
    post(client, "vuln.closure_verified")
    assert client.get("/closure/v-1/attestation", headers=tok(org=B)).status_code == 404
