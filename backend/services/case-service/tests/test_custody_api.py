"""API de custodia de punta a punta (FastAPI + SQLite): permisos, aislamiento, eventos de otros servicios,
casos que escriben en la cadena y paquete de evidencia verificable."""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import main
from app.assets import verificar_evidencia as ver
from backend.shared.database import get_db
from backend.shared.security import create_access_token
from custody_helpers import file_db

import asyncio

A, B = "org-a", "org-b"


def tok(role="admin", org=A, email="ana@acme.com", sub="u1"):
    return {"Authorization": "Bearer " + create_access_token(sub, role, org_id=org, email=email)}


def svc(org=A, name="siem-service"):
    return {"Authorization": "Bearer " + create_access_token(f"system:{name}", "admin", org_id=org)}


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


def event(**kw):
    base = {"event_type": "alert.created", "source": "siem-service", "subject_type": "alert",
            "subject_id": "al-1", "refs": ["alert:al-1"], "payload": {"rule": "ssh brute"}}
    base.update(kw)
    return base


def test_requires_login(client):
    for path in ("/custody/status", "/custody/entries", "/custody/verify", "/custody/anchor"):
        assert client.get(path).status_code == 401
    assert client.post("/custody/cases/x/package").status_code == 401
    assert client.post("/internal/custody/events", json=event()).status_code == 401


def test_internal_events_need_a_service_token_and_valid_type(client):
    assert client.post("/internal/custody/events", json=event(), headers=tok()).status_code == 403  # usuario, no servicio
    ok = client.post("/internal/custody/events", json=event(), headers=svc())
    assert ok.status_code == 201 and ok.json()["seq"] == 1
    assert client.post("/internal/custody/events", json=event(event_type="case.created"), headers=svc()).status_code == 403
    assert client.post("/internal/custody/events", json=event(event_type="evidence.exported"), headers=svc()).status_code == 403
    assert client.post("/internal/custody/events", json=event(event_type="algo.raro"), headers=svc()).status_code == 422
    assert client.post("/internal/custody/events", json=event(event_type="Alert X"), headers=svc()).status_code == 422
    assert client.post("/internal/custody/events", json=event(payload={"x": "a" * 20000}), headers=svc()).status_code == 413


def test_org_comes_from_the_token_and_chains_are_isolated(client):
    client.post("/internal/custody/events", json=event(), headers=svc(A))
    client.post("/internal/custody/events", json=event(), headers=svc(B))
    client.post("/internal/custody/events", json=event(), headers=svc(A))
    assert client.get("/custody/status", headers=tok(org=A)).json()["entries"] == 2
    assert client.get("/custody/status", headers=tok(org=B)).json()["entries"] == 1
    assert client.get("/custody/entries", headers=tok(org=B)).json()["total"] == 1
    assert client.get("/custody/verify", headers=tok(org=A)).json()["ok"] is True


def test_status_exposes_public_key_and_fingerprint(client):
    s = client.get("/custody/status", headers=tok("viewer")).json()
    assert len(s["public_key"]) == 64 and s["key_fingerprint"].count("-") == 7
    assert s["key_derived_from_jwt"] is False and s["entries"] == 0


def test_anchor_and_verify_with_anchor(client):
    client.post("/internal/custody/events", json=event(), headers=svc())
    a = client.get("/custody/anchor", headers=tok()).json()
    assert a["entries"] == 1 and len(a["signature"]) == 128
    assert client.get("/custody/verify", params={"expected_count": 1, "expected_head": a["head_hash"]}, headers=tok()).json()["ok"]
    bad = client.get("/custody/verify", params={"expected_count": 5}, headers=tok()).json()
    assert bad["ok"] is False and bad["anchor_checked"] is True


def test_case_lifecycle_writes_to_the_chain_and_package_verifies(client):
    h = tok()
    case = client.post("/cases", json={"title": "Fuerza bruta en VPN", "priority": "high", "alert_id": "al-1"}, headers=h).json()
    cid = case["id"]
    client.post("/internal/custody/events", json=event(), headers=svc())
    client.post("/internal/custody/events", json=event(event_type="soar.playbook_run", subject_type="playbook_run",
                subject_id="r1", payload={"status": "completed", "steps": [{"action": "block_ip", "simulated": True}]}), headers=svc("org-a", "soar-service"))
    client.post("/internal/custody/events", json=event(event_type="vuln.status_changed", subject_type="vuln", subject_id="v1",
                refs=["vuln:v1"], payload={"nada": "que ver"}), headers=svc())
    assert client.patch(f"/cases/{cid}", json={"status": "in_progress", "assignee": "luis"}, headers=h).status_code == 200
    assert client.post(f"/cases/{cid}/timeline", json={"action": "nota", "notes": "Se aislo el host"}, headers=h).status_code == 200
    assert client.patch(f"/cases/{cid}", json={"status": "resolved"}, headers=h).status_code == 200

    types = [e["event_type"] for e in client.get("/custody/entries", params={"limit": 50}, headers=h).json()["items"]]
    for expected in ("case.created", "case.status_changed", "case.updated", "case.note_added"):
        assert expected in types
    assert client.get("/custody/verify", headers=h).json()["ok"]

    assert client.post(f"/cases/{cid}/package", headers=h).status_code == 404  # ruta equivocada: no existe
    assert client.post(f"/custody/cases/{cid}/package", headers=tok("viewer")).status_code == 403
    assert client.post(f"/custody/cases/{cid}/package", headers=tok(org=B)).status_code == 404
    resp = client.post(f"/custody/cases/{cid}/package", headers=h)
    assert resp.status_code == 200 and resp.headers["content-type"] == "application/zip"
    assert f"evidencia-caso-{cid[:8]}" in resp.headers["content-disposition"]

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    manifest = json.loads(zf.read("manifest.json"))
    result = ver.verify_manifest(manifest)
    assert result["ok"], result["checks"]
    shown = {r["fields"]["type"] for r in manifest["chain"] if "fields" in r}
    assert {"case.created", "case.status_changed", "case.note_added", "alert.created", "soar.playbook_run",
            "evidence.exported"} <= shown
    assert "vuln.status_changed" not in shown  # de otro asunto: solo aparece como hoja oculta
    assert "nada" not in zf.read("manifest.json").decode()
    assert manifest["case"]["status"] == "resolved" and manifest["case"]["timeline"]
    assert "evidence.exported" in [e["event_type"] for e in client.get("/custody/entries", headers=h).json()["items"]]
    assert client.get("/custody/verify", headers=h).json()["ok"]


def test_import_from_soar_is_recorded(client, monkeypatch):
    # el camino de importacion usa la misma funcion que los demas: se prueba con un caso creado por la API
    h = tok()
    cid = client.post("/cases", json={"title": "t", "source": "soar-import"}, headers=h).json()["id"]
    items = client.get("/custody/entries", params={"subject_id": cid}, headers=h).json()["items"]
    assert items and items[0]["event_type"] == "case.created" and items[0]["actor"] == "ana@acme.com"
