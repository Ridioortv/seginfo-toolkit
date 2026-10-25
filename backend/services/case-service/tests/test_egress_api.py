"""Prueba de soberania de punta a punta: informes de los servicios, clasificacion, veredictos, prueba de red,
atestado firmado y su verificacion independiente."""
import asyncio
import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app import egress_catalog as cat
from app import egress_service as eg
from app import main, services
from app.assets import verificar_evidencia as ver
from backend.shared import custody_core as core
from backend.shared.database import get_db
from backend.shared.security import create_access_token
from custody_helpers import file_db

A = "org-a"


def tok(role="admin", org=A, email="ana@acme.com"):
    return {"Authorization": "Bearer " + create_access_token("u1", role, org_id=org, email=email)}


def svc(name):
    return {"Authorization": "Bearer " + create_access_token(f"system:{name}", "admin")}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")
    engine, Session = file_db()

    async def override():
        async with Session() as session:
            yield session

    async def orgs():
        return [A]

    monkeypatch.setattr(services, "list_organization_ids", orgs)
    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def report(service, isolated=False, dests=(), **kw):
    return {"service": service, "instance": "abc", "boot": "2026-10-01T00:00:00+00:00", "isolated": isolated,
            "allowlist": [], "interval_seconds": 60, "destinations": list(dests), **kw}


def dest(host, count=1, blocked=0, kind="http", purposes=()):
    return {"host": host, "kind": kind, "count": count, "blocked": blocked, "first_seen": "2026-10-01T00:00:00+00:00",
            "last_seen": "2026-10-02T00:00:00+00:00", "purposes": list(purposes)}


def send(client, service, **kw):
    r = client.post("/internal/egress/report", json=report(service, **kw), headers=svc(service))
    assert r.status_code == 204, r.text


def fresh_all(client, isolated):
    for s in cat.EXPECTED_SERVICES:
        send(client, s, isolated=isolated)


def notes(s):
    return " | ".join(n["text"].format(*n["args"]) for n in s["notes"])


def status(client):
    r = client.get("/sovereignty/status", headers=tok())
    assert r.status_code == 200, r.text
    return r.json()


def test_catalog_classification():
    assert cat.classify("vuln-service", "services.nvd.nist.gov")[0] == "catalogado"
    assert cat.classify("cloud-service", "ec2.us-east-1.amazonaws.com")[0] == "catalogado"
    assert cat.classify("coderepo-service", "gist.github.com")[0] == "catalogado"
    assert cat.classify("notification-service", "smtp.empresa.com")[0] == "configurado"
    assert cat.classify("siem-service", "smtp.empresa.com")[0] == "no_catalogado"
    # un destino catalogado para otro servicio no se da por bueno
    assert cat.classify("siem-service", "services.nvd.nist.gov")[0] == "no_catalogado"
    assert cat.host_matches("*.github.com", "github.com") and not cat.host_matches("*.github.com", "evilgithub.com")


def test_every_catalog_entry_is_documented():
    ids = set()
    for e in cat.CATALOG:
        assert e["id"] not in ids
        ids.add(e["id"])
        for key in ("host", "services", "category", "purpose", "sends", "offline"):
            assert e[key], (e["id"], key)
        assert all(s in cat.EXPECTED_SERVICES for s in e["services"])


def test_permissions(client):
    for path in ("/sovereignty/status", "/sovereignty/catalog", "/sovereignty/attestation"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers=tok("analyst")).status_code == 403
        assert client.get(path, headers=tok("soc_manager")).status_code == 200
    assert client.post("/sovereignty/probe").status_code == 401
    assert client.post("/sovereignty/probe", headers=tok("soc_manager")).status_code == 403
    # un usuario no puede informar como si fuera un servicio, ni un servicio por otro
    assert client.post("/internal/egress/report", json=report("siem-service"), headers=tok()).status_code == 403
    assert client.post("/internal/egress/report", json=report("siem-service"), headers=svc("soar-service")).status_code == 403
    assert client.post("/internal/egress/report", json=report("siem-service")).status_code == 401


def test_report_accumulates_counts_and_purposes(client):
    send(client, "vuln-service", dests=[dest("services.nvd.nist.gov", 3, 0, purposes=["CVSS"])])
    send(client, "vuln-service", dests=[dest("services.nvd.nist.gov", 2, 1, purposes=["CVSS", "otro"])])
    d = [x for x in status(client)["destinations"] if x["host"] == "services.nvd.nist.gov"]
    assert len(d) == 1 and d[0]["count"] == 5 and d[0]["blocked"] == 1
    assert d[0]["purposes"] == ["CVSS", "otro"] and d[0]["classification"] == "catalogado"
    assert d[0]["catalog"]["category"] == "Inteligencia de vulnerabilidades"


def test_no_data_then_controlled_then_unexpected(client):
    assert status(client)["verdict"] == "no_data"
    send(client, "vuln-service", dests=[dest("services.nvd.nist.gov")])
    s = status(client)
    assert s["verdict"] == "controlled" and s["summary"]["unknown_destinations"] == 0
    assert "Sin informes recientes de" in notes(s)
    send(client, "siem-service", dests=[dest("raro.ejemplo.net", 4)])
    s = status(client)
    assert s["verdict"] == "unexpected" and s["summary"]["unknown_destinations"] == 1


def test_blocked_unknown_destination_is_not_unexpected(client):
    send(client, "siem-service", dests=[dest("raro.ejemplo.net", 4, blocked=4)])
    s = status(client)
    assert s["verdict"] != "unexpected" and s["summary"]["blocked_attempts"] == 4


def test_isolated_needs_network_proof(client, monkeypatch):
    fresh_all(client, isolated=True)
    s = status(client)
    assert s["verdict"] == "isolated_unverified" and "Falta la prueba de red." in notes(s)

    async def closed(host, port, kind, timeout):
        return False, "sin respuesta (tiempo agotado)"

    monkeypatch.setattr(eg, "real_connector", closed)
    r = client.post("/sovereignty/probe", headers=tok())
    assert r.status_code == 200 and r.json()["reachable"] == 0 and r.json()["verdict"] == "isolated_verified"
    assert status(client)["verdict"] == "isolated_verified"

    async def open_(host, port, kind, timeout):
        return True, "conexion establecida"

    monkeypatch.setattr(eg, "real_connector", open_)
    r = client.post("/sovereignty/probe", headers=tok())
    assert r.json()["reachable"] == 3 and r.json()["verdict"] == "isolated_unverified"
    assert "logro salir" in notes(status(client))


def test_isolated_only_in_some_services_is_just_controlled(client):
    fresh_all(client, isolated=True)
    send(client, "siem-service", isolated=False)
    s = status(client)
    assert s["verdict"] == "controlled" and s["summary"]["isolated_services"] == len(cat.EXPECTED_SERVICES) - 1
    assert "solo en algunos" in notes(s)


def test_stale_service_counts_as_missing(client):
    fresh_all(client, isolated=True)

    async def age():
        from sqlalchemy import select
        from app.egress_models import EgressService
        from datetime import datetime, timedelta, timezone
        async for db in main.app.dependency_overrides[get_db]():
            row = (await db.execute(select(EgressService).where(EgressService.service == "asset-service"))).scalars().first()
            row.last_seen = datetime.now(timezone.utc) - timedelta(minutes=30)
            await db.commit()

    asyncio.run(age())
    s = status(client)
    assert s["verdict"] == "controlled" and "asset-service" in s["summary"]["services_missing"]


def test_probe_is_recorded_in_the_custody_chain(client, monkeypatch):
    async def closed(host, port, kind, timeout):
        return False, "x"

    monkeypatch.setattr(eg, "real_connector", closed)
    client.post("/sovereignty/probe", headers=tok())
    entries = client.get("/custody/entries", headers=tok()).json()["items"]
    assert [e["event_type"] for e in entries] == ["sovereignty.probe"]
    assert entries[0]["actor"] == "ana@acme.com" and entries[0]["payload"]["reachable"] == 0
    assert client.get("/custody/verify", headers=tok()).json()["ok"] is True


def test_mode_change_is_recorded_once(client):
    send(client, "siem-service", isolated=False)   # alta: no es un cambio
    send(client, "siem-service", isolated=False)
    send(client, "siem-service", isolated=True)
    send(client, "siem-service", isolated=True)
    entries = client.get("/custody/entries", headers=tok()).json()["items"]
    assert [e["event_type"] for e in entries] == ["sovereignty.mode_changed"]
    p = entries[0]["payload"]
    assert p == {"service": "siem-service", "isolated_before": False, "isolated_after": True}


def test_attestation_is_signed_and_verifiable_without_tero(client, tmp_path):
    send(client, "vuln-service", dests=[dest("services.nvd.nist.gov", 7)])
    r = client.get("/sovereignty/attestation", headers=tok())
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    doc = r.json()
    assert doc["kind"] == "sovereignty" and doc["body"]["destinations"][0]["host"] == "services.nvd.nist.gov"
    assert core.verify_attestation(doc)["ok"] is True
    assert core.verify_attestation(doc, doc["key_fingerprint"])["ok"] is True
    assert core.verify_attestation(doc, "0000-0000")["ok"] is False
    assert ver.verify_attestation(doc)["ok"] is True

    path = tmp_path / "atestado.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    run = subprocess.run([sys.executable, str(ver.__file__), str(path)], capture_output=True, text=True)
    assert run.returncode == 0 and "ATESTADO INTEGRO" in run.stdout

    # si alguien cambia una sola cifra, la firma deja de valer (en el nucleo y en el verificador)
    doc["body"]["destinations"][0]["count"] = 1
    assert core.verify_attestation(doc)["ok"] is False and ver.verify_attestation(doc)["ok"] is False
    path.write_text(json.dumps(doc), encoding="utf-8")
    run = subprocess.run([sys.executable, str(ver.__file__), str(path)], capture_output=True, text=True)
    assert run.returncode == 1 and "NO CONFIABLE" in run.stdout

    entries = client.get("/custody/entries", headers=tok()).json()["items"]
    assert entries[0]["event_type"] == "sovereignty.attestation"


def test_attestation_rejects_foreign_or_malformed_documents(client):
    assert core.verify_attestation({})["ok"] is False
    doc = core.make_attestation("sovereignty", A, {"verdict": "x"})
    assert core.verify_attestation({**doc, "kind": "compliance"})["ok"] is False
    assert core.verify_attestation({**doc, "organization_id": "otra"})["ok"] is False
    assert core.verify_attestation({**doc, "format": "otro"})["ok"] is False
    assert ver.verify_attestation({**doc, "kind": "compliance"})["ok"] is False


def test_real_connector_reaches_local_port_and_fails_on_closed_one():
    async def run():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            ok = await eg.real_connector("127.0.0.1", port, "tcp", 2)
        finally:
            server.close()
            await server.wait_closed()
        bad = await eg.real_connector("127.0.0.1", port, "tcp", 2)
        return ok, bad

    ok, bad = asyncio.run(run())
    assert ok[0] is True and bad[0] is False


def test_probe_targets_override(monkeypatch):
    monkeypatch.setenv("TERO_PROBE_TARGETS", "192.0.2.1:8080, otro.test")
    assert eg.probe_targets() == [("192.0.2.1", 8080, "tcp"), ("otro.test", 443, "tcp")]


def test_catalog_endpoint(client):
    items = client.get("/sovereignty/catalog", headers=tok()).json()
    assert any(i["id"] == "nvd" for i in items)


def test_network_exceptions_are_reported(client, monkeypatch):
    monkeypatch.setenv("TERO_NETWORK_EXCEPTIONS", "scan-service")
    fresh_all(client, isolated=True)

    async def closed(host, port, kind, timeout):
        return False, "x"

    monkeypatch.setattr(eg, "real_connector", closed)
    client.post("/sovereignty/probe", headers=tok())
    s = status(client)
    assert s["verdict"] == "isolated_verified" and s["network_exceptions"] == ["scan-service"]
    assert "scan-service" in notes(s)
    doc = client.get("/sovereignty/attestation", headers=tok()).json()
    assert doc["body"]["network_exceptions"] == ["scan-service"]
