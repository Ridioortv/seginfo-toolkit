"""Tickets vinculados: adaptadores de Jira/ServiceNow, creacion, la vuelta por webhook y por consulta, y aislamiento."""
import asyncio
import json
import os
import tempfile

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import main
from app import ticket_providers as prov
from app import ticket_service as svc
from app.models import Base, TicketLog
from backend.shared.crypto import encrypt_secret
from backend.shared.database import get_db
from backend.shared.security import create_access_token

A, B = "org-a", "org-b"


def tok(role="analyst", org=A, email="ana@acme.com"):
    return {"Authorization": "Bearer " + create_access_token(email, role, org_id=org, email=email)}


# ------------------------------ adaptadores ------------------------------

class Fake:
    """Sistema de tickets falso: {metodo, ruta} -> (status, json). Guarda las llamadas."""

    def __init__(self):
        self.routes = {}
        self.calls = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path, request.url.query.decode(), request.headers.get("authorization", ""), request.content))
        for (method, path), (status, body) in self.routes.items():
            if request.method == method and request.url.path.startswith(path):
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={})


@pytest.fixture()
def fake(monkeypatch):
    f = Fake()
    monkeypatch.setattr(prov, "validate_outbound_url", lambda *a, **k: None)
    monkeypatch.setattr(prov, "_client", lambda auth=None: httpx.AsyncClient(transport=httpx.MockTransport(f.handler), auth=auth))
    return f


JIRA = {"provider": "jira", "base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "api_token": encrypt_secret("tok-jira"), "project_key": "SEC"}
SNOW = {"provider": "servicenow", "base_url": "https://acme.service-now.com", "username": "tero", "api_token": encrypt_secret("pw-snow")}


def run(coro):
    return asyncio.run(coro)


def test_jira_create_and_status_mapping(fake):
    fake.routes[("POST", "/rest/api/2/issue")] = (201, {"key": "SEC-7", "id": "10007"})
    c = run(prov.create(JIRA, "Titulo", "Desc", "high"))
    assert c.key == "SEC-7" and c.url == "https://acme.atlassian.net/browse/SEC-7"
    body = json.loads(fake.calls[0][4])["fields"]
    assert body["project"] == {"key": "SEC"} and body["summary"] == "Titulo" and fake.calls[0][3].startswith("Basic ")

    def state(cat, res=None):
        fake.routes[("GET", "/rest/api/2/issue/SEC-7")] = (200, {"fields": {"status": {"name": "X", "statusCategory": {"key": cat}}, "resolution": {"name": res} if res else None}})
        return run(prov.fetch_status(JIRA, "SEC-7")).state

    assert state("new") == "open" and state("indeterminate") == "open"
    assert state("done", "Fixed") == "resolved" and state("done", "Done") == "resolved"
    assert state("done", "Won't Do") == "canceled" and state("done", "Duplicate") == "canceled"


def test_servicenow_create_and_status_mapping(fake):
    fake.routes[("POST", "/api/now/table/incident")] = (201, {"result": {"sys_id": "abc123", "number": "INC0010001"}})
    c = run(prov.create(SNOW, "T", "D", "critical"))
    assert c.key == "INC0010001" and c.external_id == "abc123" and "sys_id%3Dabc123" in c.url
    sent = json.loads(fake.calls[0][4])
    assert sent["impact"] == "1" and sent["urgency"] == "1" and sent["short_description"] == "T"

    def state(s):
        fake.routes[("GET", "/api/now/table/incident/abc123")] = (200, {"result": {"state": s}})
        return run(prov.fetch_status(SNOW, "INC0010001", "abc123")).state

    assert state("1") == "open" and state("2") == "open" and state("3") == "open"
    assert state("6") == "resolved" and state("7") == "resolved" and state("8") == "canceled"
    fake.routes[("GET", "/api/now/table/incident")] = (200, {"result": [{"state": "6"}]})
    assert run(prov.fetch_status(SNOW, "INC0010001", "")).state == "resolved"   # sin sys_id: busca por numero


def test_provider_errors_never_leak_url_or_secret(fake):
    for status, expect in ((401, "credenciales"), (403, "credenciales"), (404, "404"), (500, "HTTP 500")):
        fake.routes = {("POST", "/rest/api/2/issue"): (status, {})}
        with pytest.raises(prov.ProviderError) as e:
            run(prov.create(JIRA, "t", "d", "low"))
        msg = str(e.value)
        assert expect in msg and "atlassian" not in msg and "tok-jira" not in msg
    with pytest.raises(prov.ProviderError):
        run(prov.create({**JIRA, "api_token": ""}, "t", "d", "low"))
    with pytest.raises(prov.ProviderError):
        run(prov.create({**SNOW, "table": "x;drop"}, "t", "d", "low"))


def test_unsafe_url_is_rejected_by_ssrf_guard():
    with pytest.raises(prov.ProviderError):
        run(prov.create({**JIRA, "base_url": "http://169.254.169.254"}, "t", "d", "low"))
    with pytest.raises(prov.ProviderError):
        run(prov.create({**JIRA, "base_url": "http://localhost:8000"}, "t", "d", "low"))


def test_check_connection(fake):
    fake.routes[("GET", "/rest/api/2/myself")] = (200, {})
    fake.routes[("GET", "/rest/api/2/project/SEC")] = (200, {})
    assert "Jira" in run(prov.check(JIRA))
    fake.routes[("GET", "/rest/api/2/project/SEC")] = (404, {})
    with pytest.raises(prov.ProviderError):
        run(prov.check(JIRA))


# ------------------------------ servicio y rutas ------------------------------

class World:
    """Lo que hay del otro lado: vulnerabilidades y casos, y un registro de lo que TERO les hizo."""

    def __init__(self):
        self.subjects = {}
        self.applied = []
        self.chat = []


@pytest.fixture()
def env(monkeypatch, fake):
    monkeypatch.setenv("TERO_CUSTODY_DISABLED", "1")
    monkeypatch.setenv("INTEGRATION_DRY_RUN", "false")
    world = World()
    world.subjects[(A, "vulnerability", "v1")] = {"id": "v1", "title": "Panel expuesto", "severity": "high", "status": "open", "cve_id": "CVE-2026-1",
                                                  "is_kev": True, "cvss_score": 8.1, "port": 8443, "description": "Detalle", "remediation_steps": ["Actualizar"]}
    world.subjects[(A, "vulnerability", "v2")] = {"id": "v2", "title": "Otra", "severity": "medium", "status": "open"}
    world.subjects[(A, "vulnerability", "vdone")] = {"id": "vdone", "title": "Hecha", "severity": "high", "status": "remediated"}
    world.subjects[(A, "case", "c1")] = {"id": "c1", "title": "Phishing", "priority": "high", "status": "open", "description": "Mail sospechoso"}
    world.subjects[(B, "vulnerability", "vb")] = {"id": "vb", "title": "De B", "severity": "high", "status": "open"}

    async def service_get(url, org):
        for (o, kind, sid), data in world.subjects.items():
            if o == org and url.endswith(("/internal/vulnerabilities/" if kind == "vulnerability" else "/cases/") + sid):
                return data
        raise svc.TicketError("No se encontro lo que queres vincular", 404)

    async def apply_vuln(link):
        world.applied.append(("vulnerability", link.subject_id, link.external_key))
        return "Vulnerabilidad marcada como remediada; arranco la verificacion con un nuevo escaneo"

    async def apply_case(link):
        world.applied.append(("case", link.subject_id, link.external_key))
        return "Caso marcado como resuelto"

    async def chat(connector, subject, body, severity):
        world.chat.append(subject)

    monkeypatch.setattr(svc, "_service_get", service_get)
    monkeypatch.setattr(svc, "_apply_vulnerability", apply_vuln)
    monkeypatch.setattr(svc, "_apply_case", apply_case)
    monkeypatch.setattr(svc, "notify_chat", chat)
    path = os.path.join(tempfile.mkdtemp(prefix="integ-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app), fake, world, Session
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def add_connector(client, cfg=None, org=A, name="Jira SEC"):
    r = client.post("/connectors", headers=tok("admin", org), json={"name": name, "kind": "ticketing", "config": cfg or {
        "provider": "jira", "base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "api_token": "tok-jira", "project_key": "SEC"}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def jira_state(fake, key, cat, res=None):
    fake.routes[("GET", f"/rest/api/2/issue/{key}")] = (200, {"fields": {"status": {"name": "Estado", "statusCategory": {"key": cat}}, "resolution": {"name": res} if res else None}})


def make_link(client, fake, subject="v1", kind="vulnerability", key="SEC-1", org=A, headers=None):
    fake.routes[("POST", "/rest/api/2/issue")] = (201, {"key": key, "id": "1001"})
    return client.post("/ticket-links", headers=headers or tok("analyst", org), json={"subject_type": kind, "subject_id": subject})


def test_create_ticket_for_vulnerability_builds_a_useful_ticket(env):
    client, fake, world, _ = env
    add_connector(client)
    r = make_link(client, fake)
    assert r.status_code == 201, r.text
    link = r.json()
    assert link["state"] == "open" and link["external_key"] == "SEC-1" and link["external_url"].endswith("/browse/SEC-1") and link["provider"] == "jira"
    fields = json.loads(fake.calls[-1][4])["fields"]
    assert fields["summary"].startswith("[TERO][Alta]") and "CVE-2026-1" in fields["description"] and "KEV" in fields["description"] \
        and "Actualizar" in fields["description"] and "escanear" in fields["description"]
    assert "tok-jira" not in json.dumps(client.get("/connectors", headers=tok()).json())  # la clave nunca se devuelve
    # el credencial viaja como Basic, no en el cuerpo
    assert fake.calls[-1][3].startswith("Basic ")


def test_ticket_for_case_and_validation(env):
    client, fake, world, _ = env
    add_connector(client)
    assert make_link(client, fake, "c1", "case", "SEC-5").status_code == 201
    assert make_link(client, fake, "vdone").status_code == 409                       # ya remediada
    assert make_link(client, fake, "nope").status_code == 404
    assert client.post("/ticket-links", headers=tok(), json={"subject_type": "alerta", "subject_id": "x"}).status_code == 422


def test_duplicate_is_rejected_and_points_to_existing(env):
    client, fake, _, _ = env
    add_connector(client)
    first = make_link(client, fake).json()
    again = make_link(client, fake)
    assert again.status_code == 409 and again.json()["detail"]["link_id"] == first["id"] and again.json()["detail"]["external_key"] == "SEC-1"


def test_needs_connector_and_roles(env):
    client, fake, _, _ = env
    assert make_link(client, fake).status_code == 409                                  # sin conector
    add_connector(client)
    assert make_link(client, fake, headers=tok("viewer")).status_code == 403
    assert client.get("/ticket-links", headers=tok("viewer")).status_code == 200      # puede ver
    assert client.get("/ticket-links").status_code == 401
    assert client.post("/connectors/x/webhook-secret", headers=tok("analyst")).status_code == 403


def test_provider_failure_returns_502_without_link_and_logs_attempt(env):
    client, fake, _, Session = env
    add_connector(client)
    fake.routes[("POST", "/rest/api/2/issue")] = (401, {})
    r = client.post("/ticket-links", headers=tok(), json={"subject_type": "vulnerability", "subject_id": "v1"})
    assert r.status_code == 502 and "credenciales" in r.text and "atlassian" not in r.text
    assert client.get("/ticket-links", headers=tok()).json() == []

    async def count():
        async with Session() as s:
            return [row[0] for row in (await s.execute(select(TicketLog.status))).all()]
    assert asyncio.run(count()) == ["failed"]


def test_dry_run_creates_simulated_link_without_calling_anything(env, monkeypatch):
    client, fake, _, _ = env
    monkeypatch.setenv("INTEGRATION_DRY_RUN", "true")
    add_connector(client)
    r = make_link(client, fake)
    assert r.status_code == 201 and r.json()["state"] == "simulated" and r.json()["external_key"] == "" and fake.calls == []
    assert client.post("/ticket-links/sync", headers=tok("admin")).status_code == 409


def webhook_path(client, cid, org=A):
    r = client.post(f"/connectors/{cid}/webhook-secret", headers=tok("admin", org))
    assert r.status_code == 200, r.text
    return r.json()["path"]


def test_webhook_resolves_ticket_once_and_asks_the_provider(env):
    client, fake, world, _ = env
    cid = add_connector(client)
    path = webhook_path(client, cid)
    assert "••" not in path and path.startswith(f"/public/ticket-webhooks/{cid}/")
    make_link(client, fake)
    # el aviso dice "Done" pero el sistema real todavia dice abierto: TERO no se fia del aviso
    jira_state(fake, "SEC-1", "indeterminate")
    r = client.post(path, json={"issue": {"key": "SEC-1"}, "issue_status": "Done"})
    assert r.status_code == 200 and r.json() == {"matched": 1, "synced": 1}
    assert world.applied == [] and client.get("/ticket-links", headers=tok()).json()[0]["state"] == "open"
    # ahora si se resolvio
    jira_state(fake, "SEC-1", "done", "Fixed")
    assert client.post(path, json={"issue": {"key": "SEC-1"}}).json()["synced"] == 1
    link = client.get("/ticket-links?subject_type=vulnerability&subject_id=v1", headers=tok()).json()[0]
    assert link["state"] == "resolved" and link["applied"] is True and "verificacion" in link["applied_note"]
    assert world.applied == [("vulnerability", "v1", "SEC-1")]
    # otro aviso del mismo ticket no vuelve a aplicar nada
    client.post(path, json={"issue": {"key": "SEC-1"}})
    assert world.applied == [("vulnerability", "v1", "SEC-1")]
    assert any("resuelto" in c for c in world.chat)


def test_webhook_secret_is_required_and_uniform_404(env):
    client, fake, world, _ = env
    cid = add_connector(client)
    path = webhook_path(client, cid)
    make_link(client, fake)
    jira_state(fake, "SEC-1", "done", "Fixed")
    assert client.post(f"/public/ticket-webhooks/{cid}/mal-secreto", json={"issue": {"key": "SEC-1"}}).status_code == 404
    assert client.post(f"/public/ticket-webhooks/no-existe/{path.rsplit('/', 1)[1]}", json={}).status_code == 404
    assert world.applied == []
    # secreto nuevo: el anterior deja de valer
    new_path = webhook_path(client, cid)
    assert new_path != path and client.post(path, json={"issue": {"key": "SEC-1"}}).status_code == 404
    assert client.post(new_path, json={"issue": {"key": "SEC-1"}}).status_code == 200 and len(world.applied) == 1
    # el hash del secreto no se devuelve en la API
    listed = json.dumps(client.get("/connectors", headers=tok()).json())
    assert "_webhook" not in listed and "sha256" not in listed and '"webhook_enabled": true' in listed


def test_webhook_secret_survives_editing_the_connector_and_keeps_api_token(env):
    client, fake, _, _ = env
    cid = add_connector(client)
    path = webhook_path(client, cid)
    r = client.patch(f"/connectors/{cid}", headers=tok("admin"), json={"config": {"provider": "jira", "base_url": "https://acme.atlassian.net", "email": "bot@acme.com",
                                                                                 "api_token": "••••••••", "project_key": "SEC", "_webhook_sha256": "forzado"}})
    assert r.status_code == 200
    make_link(client, fake)
    jira_state(fake, "SEC-1", "done", "Fixed")
    assert client.post(path, json={"issue": {"key": "SEC-1"}}).json()["synced"] == 1          # el secreto sigue valiendo
    assert client.post(f"/public/ticket-webhooks/{cid}/forzado", json={"issue": {"key": "SEC-1"}}).status_code == 404   # y no se puede imponer uno
    assert fake.calls[-1][3].startswith("Basic ")                                                # el api_token se conservo (cifrado)


def test_closed_without_fix_leaves_the_vulnerability_alone(env):
    client, fake, world, _ = env
    cid = add_connector(client)
    path = webhook_path(client, cid)
    make_link(client, fake)
    jira_state(fake, "SEC-1", "done", "Won't Do")
    client.post(path, json={"issue": {"key": "SEC-1"}})
    link = client.get("/ticket-links", headers=tok()).json()[0]
    assert link["state"] == "closed_no_fix" and link["applied"] is False and world.applied == [] and "sigue abierta" in link["applied_note"]
    # y se puede abrir otro ticket despues
    fake.routes[("POST", "/rest/api/2/issue")] = (201, {"key": "SEC-2", "id": "1002"})
    assert client.post("/ticket-links", headers=tok(), json={"subject_type": "vulnerability", "subject_id": "v1"}).status_code == 201


def test_case_ticket_resolution_updates_case(env):
    client, fake, world, _ = env
    cid = add_connector(client)
    path = webhook_path(client, cid)
    make_link(client, fake, "c1", "case", "SEC-9")
    jira_state(fake, "SEC-9", "done", "Done")
    client.post(path, json={"issue": {"key": "SEC-9"}})
    assert world.applied == [("case", "c1", "SEC-9")]


def test_polling_sync_without_webhook_and_failure_is_retried(env):
    client, fake, world, _ = env
    add_connector(client)
    make_link(client, fake)
    fake.routes[("GET", "/rest/api/2/issue/SEC-1")] = (500, {})                    # el sistema externo falla: no se pierde nada
    r = client.post("/ticket-links/sync", headers=tok("admin"))
    assert r.status_code == 200 and r.json() == {"checked": 1, "changed": 0}
    link = client.get("/ticket-links", headers=tok()).json()[0]
    assert link["state"] == "open" and "HTTP 500" in link["last_error"] and "atlassian" not in link["last_error"]
    jira_state(fake, "SEC-1", "done", "Fixed")
    assert client.post("/ticket-links/sync", headers=tok("admin")).json() == {"checked": 1, "changed": 1}
    assert world.applied == [("vulnerability", "v1", "SEC-1")]
    assert client.post("/ticket-links/sync", headers=tok("analyst")).status_code == 403   # solo admin / soc_manager


def test_apply_failure_is_retried_next_cycle(env, monkeypatch):
    client, fake, world, _ = env
    add_connector(client)
    make_link(client, fake)
    jira_state(fake, "SEC-1", "done", "Fixed")

    async def broken(link):
        raise svc.TicketError("No pude avisarle a vuln-service; se reintenta en el proximo ciclo", 502)

    good = svc._apply_vulnerability
    monkeypatch.setattr(svc, "_apply_vulnerability", broken)
    client.post("/ticket-links/sync", headers=tok("admin"))
    link = client.get("/ticket-links", headers=tok()).json()[0]
    assert link["applied"] is False and "reintenta" in link["last_error"]
    monkeypatch.setattr(svc, "_apply_vulnerability", good)
    client.post("/ticket-links/sync", headers=tok("admin"))
    assert client.get("/ticket-links", headers=tok()).json()[0]["applied"] is True and len(world.applied) == 1


def test_reopened_externally_goes_back_to_open(env):
    client, fake, world, _ = env
    add_connector(client)
    make_link(client, fake)
    jira_state(fake, "SEC-1", "done", "Fixed")
    client.post("/ticket-links/sync", headers=tok("admin"))
    jira_state(fake, "SEC-1", "indeterminate")
    link_id = client.get("/ticket-links", headers=tok()).json()[0]["id"]
    r = client.post(f"/ticket-links/{link_id}/sync", headers=tok())
    assert r.json()["state"] == "open" and r.json()["applied"] is False


def test_tenant_isolation(env):
    client, fake, world, _ = env
    cid_a = add_connector(client, org=A)
    add_connector(client, org=B, name="Jira B")
    make_link(client, fake)
    assert client.get("/ticket-links", headers=tok(org=B)).json() == []
    assert make_link(client, fake, "v1", org=B).status_code == 404                  # la vulnerabilidad de A no existe para B
    link_id = client.get("/ticket-links", headers=tok(org=A)).json()[0]["id"]
    assert client.post(f"/ticket-links/{link_id}/sync", headers=tok(org=B)).status_code == 404
    assert client.post(f"/connectors/{cid_a}/webhook-secret", headers=tok("admin", B)).status_code == 404
    assert client.post(f"/connectors/{cid_a}/test", headers=tok("admin", B)).status_code == 404
    # el webhook de B no toca tickets de A aunque conozca la clave
    cid_b = client.get("/connectors", headers=tok(org=B)).json()[0]["id"]
    path_b = webhook_path(client, cid_b, B)
    jira_state(fake, "SEC-1", "done", "Fixed")
    assert client.post(path_b, json={"issue": {"key": "SEC-1"}}).json() == {"matched": 0, "synced": 0}
    assert world.applied == []


def test_connector_test_endpoint(env):
    client, fake, _, _ = env
    cid = add_connector(client)
    fake.routes[("GET", "/rest/api/2/myself")] = (200, {})
    fake.routes[("GET", "/rest/api/2/project/SEC")] = (200, {})
    assert client.post(f"/connectors/{cid}/test", headers=tok("admin")).json()["ok"] is True
    fake.routes[("GET", "/rest/api/2/myself")] = (401, {})
    r = client.post(f"/connectors/{cid}/test", headers=tok("admin")).json()
    assert r["ok"] is False and "credenciales" in r["message"]


def test_connector_provider_is_validated(env):
    client, *_ = env
    r = client.post("/connectors", headers=tok("admin"), json={"name": "x", "kind": "ticketing", "config": {"provider": "otro"}})
    assert r.status_code == 422


def test_extract_refs_from_jira_servicenow_and_generic_payloads():
    assert svc.extract_refs({"issue": {"key": "SEC-1", "id": "10"}}) == ["SEC-1", "10"]
    assert svc.extract_refs({"number": "INC001", "sys_id": "abc"}) == ["INC001", "abc"]
    assert svc.extract_refs({"key": "X-1"}) == ["X-1"] and svc.extract_refs({}) == [] and svc.extract_refs({"issue": "texto"}) == []
    assert svc.extract_refs({"key": "x" * 500}) == []
