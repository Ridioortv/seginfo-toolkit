"""Tests HTTP (FastAPI TestClient) de los endpoints /openvas/* del
dashboard (configs/credenciales/targets/tasks/reportes) -- sin DB real
(las rutas de este archivo hablan con gvmd via app/gvm_manage.py, siempre
mockeado aca, igual que test_gvm_manage.py mockea gvm_query un nivel mas
abajo) y sin JWT real: se overridea get_current_claims con
dependency_overrides (mismo mecanismo que usa FastAPI para testing).

Tambien se overridea get_db (sin Postgres real en este archivo) y se
mockean las funciones de aislamiento multi-tenant de app.services
(record_gvm_resource_ownership / filter_gvm_resources_by_org / etc, ver su
docstring en app/services.py) con defaults pass-through de un solo org
("org1") -- la logica REAL de esas funciones (que es la que de verdad
importa para la seguridad: que organizacion le gana a cual) se prueba
aparte, sin mocks, en test_gvm_tenancy_helpers.py. Los tests
"..._hides_other_org_..." / "..._denied_for_other_org" de mas abajo
verifican que main.py SI aplica el resultado de esas funciones (no solo
que las llama) simulando, via override puntual, un recurso que pertenece
a OTRA organizacion."""
import os

import pytest
from fastapi.testclient import TestClient

import app.gvm_manage as gm
import app.main as m
import app.services as svc


class _FakeDbSession:
    """Placeholder para Depends(get_db) en estos tests -- las fakes de
    app.services (ver _default_ownership_fakes) nunca tocan `db` de
    verdad, pero main.py si llama a db.commit() despues, asi que alcanza
    con que exista como no-op."""

    async def commit(self):
        pass


async def _fake_get_db():
    yield _FakeDbSession()


@pytest.fixture
def client():
    def fake_claims():
        return {"sub": "tester", "org_id": "org1", "role": "admin"}

    m.app.dependency_overrides[m.get_current_claims] = fake_claims
    m.app.dependency_overrides[m.get_db] = _fake_get_db
    os.environ["GVM_USER"] = "admin"
    os.environ["GVM_PASSWORD"] = "pw"
    try:
        yield TestClient(m.app)
    finally:
        m.app.dependency_overrides.pop(m.get_current_claims, None)
        m.app.dependency_overrides.pop(m.get_db, None)
        os.environ.pop("GVM_USER", None)
        os.environ.pop("GVM_PASSWORD", None)
        os.environ.pop("GVM_SOCKET_PATH", None)


@pytest.fixture
def patch_gvm_manage(monkeypatch):
    def _patch(**fakes):
        for name, fn in fakes.items():
            monkeypatch.setattr(gm, name, fn)
    return _patch


@pytest.fixture
def patch_services(monkeypatch):
    def _patch(**fakes):
        for name, fn in fakes.items():
            monkeypatch.setattr(svc, name, fn)
    return _patch


@pytest.fixture(autouse=True)
def _default_ownership_fakes(patch_services):
    """Defaults pass-through: en estos tests, con un solo org ("org1",
    ver fake_claims arriba), el aislamiento multi-tenant de recursos GVM
    no debe cambiar nada observable salvo que algun test override
    puntualmente una de estas fakes para simular un recurso de otra
    organizacion."""
    async def _record(db, organization_id, resource_type, gvm_id):
        pass

    async def _forget(db, resource_type, gvm_id):
        pass

    async def _filter_passthrough(db, resource_type, items, organization_id):
        return items

    async def _resolve_same_org(db, resource_type, gvm_id):
        return "org1"

    async def _task_org_map(db):
        return {"tk1": "org1"}

    async def _resolve_task_org(db, task_id):
        return "org1"

    patch_services(
        record_gvm_resource_ownership=_record,
        forget_gvm_resource_ownership=_forget,
        filter_gvm_resources_by_org=_filter_passthrough,
        resolve_gvm_resource_org=_resolve_same_org,
        gvm_task_org_map=_task_org_map,
        resolve_gvm_task_org=_resolve_task_org,
    )


def test_requires_openvas_activated_first(client):
    os.environ.pop("GVM_USER", None)
    r = client.get("/openvas/configs")
    assert r.status_code == 409


def test_list_configs(client, patch_gvm_manage):
    async def fake_list_configs(socket_path, user, password):
        return True, [{"id": "c1", "name": "Full and fast"}], ""

    patch_gvm_manage(list_configs=fake_list_configs)
    r = client.get("/openvas/configs")
    assert r.status_code == 200
    assert r.json() == [{"id": "c1", "name": "Full and fast"}]


def test_list_configs_propagates_gvm_error_as_502(client, patch_gvm_manage):
    async def fake_list_configs(socket_path, user, password):
        return False, [], "gvmd no responde"

    patch_gvm_manage(list_configs=fake_list_configs)
    r = client.get("/openvas/configs")
    assert r.status_code == 502
    assert "gvmd no responde" in r.json()["detail"]


def test_credentials_create_list_delete_roundtrip(client, patch_gvm_manage):
    created = {}

    async def fake_create_credential(socket_path, user, password, name, login, secret):
        created["args"] = (name, login, secret)
        return True, "newcred", ""

    async def fake_list_credentials(socket_path, user, password):
        return True, [{"id": "newcred", "name": "root-ssh", "login": "root", "type": "up"}], ""

    async def fake_delete_credential(socket_path, user, password, credential_id):
        assert credential_id == "newcred"
        return True, ""

    patch_gvm_manage(
        create_credential=fake_create_credential,
        list_credentials=fake_list_credentials,
        delete_credential=fake_delete_credential,
    )

    r = client.post("/openvas/credentials", json={"name": "root-ssh", "login": "root", "password": "s3cr3t"})
    assert r.status_code == 201
    assert r.json() == {"id": "newcred", "name": "root-ssh", "login": "root", "credential_type": "up"}
    assert created["args"] == ("root-ssh", "root", "s3cr3t")

    r = client.get("/openvas/credentials")
    assert r.status_code == 200
    assert r.json()[0]["id"] == "newcred"

    r = client.delete("/openvas/credentials/newcred")
    assert r.status_code == 204


def test_create_credential_rejects_empty_password(client, patch_gvm_manage):
    r = client.post("/openvas/credentials", json={"name": "x", "login": "root", "password": ""})
    assert r.status_code == 422


def test_targets_create_rejects_invalid_hosts(client, patch_gvm_manage):
    r = client.post("/openvas/targets", json={"name": "bad", "hosts": "; rm -rf /", "port_list_id": "pl1"})
    assert r.status_code == 422


def test_targets_create_and_list(client, patch_gvm_manage):
    async def fake_create_target(socket_path, user, password, name, hosts, port_list_id, ssh_credential_id=None, smb_credential_id=None):
        assert (name, hosts, port_list_id) == ("Oficina", "10.0.0.0/24", "pl1")
        return True, "newtarget", ""

    async def fake_list_targets(socket_path, user, password):
        return True, [{
            "id": "newtarget", "name": "Oficina", "hosts": "10.0.0.0/24",
            "port_list_id": "pl1", "ssh_credential_id": None, "smb_credential_id": None,
        }], ""

    patch_gvm_manage(create_target=fake_create_target, list_targets=fake_list_targets)

    r = client.post("/openvas/targets", json={"name": "Oficina", "hosts": "10.0.0.0/24", "port_list_id": "pl1"})
    assert r.status_code == 201
    assert r.json()["id"] == "newtarget"

    r = client.get("/openvas/targets")
    assert r.status_code == 200
    assert r.json()[0]["name"] == "Oficina"


def test_list_tasks(client, patch_gvm_manage):
    async def fake_list_tasks(socket_path, user, password):
        return True, [{
            "id": "tk1", "name": "sentinelops-x-1", "status": "Done",
            "progress": 100, "target_id": "t1", "last_report_id": "rep1",
        }], ""

    patch_gvm_manage(list_tasks=fake_list_tasks)
    r = client.get("/openvas/tasks")
    assert r.status_code == 200
    assert r.json()[0]["last_report_id"] == "rep1"


def test_get_report_and_export(client, patch_gvm_manage):
    async def fake_list_tasks(socket_path, user, password):
        return True, [{
            "id": "tk1", "name": "sentinelops-x-1", "status": "Done",
            "progress": 100, "target_id": "t1", "last_report_id": "rep1",
        }], ""

    async def fake_get_report_xml(socket_path, user, password, report_id):
        assert report_id == "rep1"
        return True, "<report/>", ""

    async def fake_export_report(socket_path, user, password, report_id, fmt):
        assert fmt == "pdf"
        return True, b"PDFDATA", "sentinelops-report-rep1.pdf", ""

    patch_gvm_manage(
        list_tasks=fake_list_tasks, get_report_xml=fake_get_report_xml, export_report=fake_export_report,
    )

    r = client.get("/openvas/reports/rep1")
    assert r.status_code == 200
    assert r.json()["raw_xml"] == "<report/>"

    r = client.get("/openvas/reports/rep1/export?format=pdf")
    assert r.status_code == 200
    assert r.content == b"PDFDATA"
    assert "attachment" in r.headers["content-disposition"]
    assert "sentinelops-report-rep1.pdf" in r.headers["content-disposition"]


def test_export_report_gvm_failure_is_502(client, patch_gvm_manage):
    async def fake_list_tasks(socket_path, user, password):
        return True, [], ""

    async def fake_export_report(socket_path, user, password, report_id, fmt):
        return False, None, None, "formato no soportado"

    patch_gvm_manage(list_tasks=fake_list_tasks, export_report=fake_export_report)
    r = client.get("/openvas/reports/rep1/export?format=docx")
    assert r.status_code == 502


# --- Aislamiento multi-tenant: main.py SI aplica lo que dice app.services -

def test_credentials_list_hides_resource_owned_by_other_org(client, patch_gvm_manage, patch_services):
    async def fake_list_credentials(socket_path, user, password):
        return True, [{"id": "foreign-cred", "name": "root-ssh", "login": "root", "type": "up"}], ""

    async def fake_filter_hides_foreign(db, resource_type, items, organization_id):
        assert resource_type == "credential"
        return [i for i in items if i["id"] != "foreign-cred"]

    patch_gvm_manage(list_credentials=fake_list_credentials)
    patch_services(filter_gvm_resources_by_org=fake_filter_hides_foreign)

    r = client.get("/openvas/credentials")
    assert r.status_code == 200
    assert r.json() == []


def test_delete_credential_denied_for_other_org(client, patch_gvm_manage, patch_services):
    delete_called = {"value": False}

    async def fake_delete_credential(socket_path, user, password, credential_id):
        delete_called["value"] = True
        return True, ""

    async def fake_resolve_other_org(db, resource_type, gvm_id):
        return "org-ajeno"

    patch_gvm_manage(delete_credential=fake_delete_credential)
    patch_services(resolve_gvm_resource_org=fake_resolve_other_org)

    r = client.delete("/openvas/credentials/foreign-cred")
    assert r.status_code == 404
    assert delete_called["value"] is False  # nunca se le pidio el borrado real a gvmd


def test_delete_target_denied_for_other_org(client, patch_gvm_manage, patch_services):
    delete_called = {"value": False}

    async def fake_delete_target(socket_path, user, password, target_id):
        delete_called["value"] = True
        return True, ""

    async def fake_resolve_other_org(db, resource_type, gvm_id):
        return "org-ajeno"

    patch_gvm_manage(delete_target=fake_delete_target)
    patch_services(resolve_gvm_resource_org=fake_resolve_other_org)

    r = client.delete("/openvas/targets/foreign-target")
    assert r.status_code == 404
    assert delete_called["value"] is False


def test_list_tasks_hides_task_owned_by_other_org(client, patch_gvm_manage, patch_services):
    async def fake_list_tasks(socket_path, user, password):
        return True, [{
            "id": "foreign-task", "name": "sentinelops-x-1", "status": "Done",
            "progress": 100, "target_id": "t1", "last_report_id": "rep-foreign",
        }], ""

    async def fake_task_org_map(db):
        return {"foreign-task": "org-ajeno"}

    patch_gvm_manage(list_tasks=fake_list_tasks)
    patch_services(gvm_task_org_map=fake_task_org_map)

    r = client.get("/openvas/tasks")
    assert r.status_code == 200
    assert r.json() == []


def test_delete_task_denied_for_other_org(client, patch_gvm_manage, patch_services):
    delete_called = {"value": False}

    async def fake_delete_task(socket_path, user, password, task_id):
        delete_called["value"] = True
        return True, ""

    async def fake_resolve_task_other_org(db, task_id):
        return "org-ajeno"

    patch_gvm_manage(delete_task=fake_delete_task)
    patch_services(resolve_gvm_task_org=fake_resolve_task_other_org)

    r = client.delete("/openvas/tasks/foreign-task")
    assert r.status_code == 404
    assert delete_called["value"] is False


def test_get_report_denied_when_owning_task_is_other_org(client, patch_gvm_manage, patch_services):
    async def fake_list_tasks(socket_path, user, password):
        return True, [{
            "id": "foreign-task", "name": "sentinelops-x-1", "status": "Done",
            "progress": 100, "target_id": "t1", "last_report_id": "rep-foreign",
        }], ""

    async def fake_resolve_task_other_org(db, task_id):
        return "org-ajeno"

    patch_gvm_manage(list_tasks=fake_list_tasks)
    patch_services(resolve_gvm_task_org=fake_resolve_task_other_org)

    r = client.get("/openvas/reports/rep-foreign")
    assert r.status_code == 404
