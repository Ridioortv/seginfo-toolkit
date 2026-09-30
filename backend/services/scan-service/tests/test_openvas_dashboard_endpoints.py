"""Tests HTTP (FastAPI TestClient) de los endpoints /openvas/* del
dashboard (configs/credenciales/targets/tasks/reportes) -- sin DB real
(las rutas de este archivo no tocan la base, solo hablan con gvmd via
app/gvm_manage.py) y sin JWT real: se overridea get_current_claims con
dependency_overrides (mismo mecanismo que usa FastAPI para testing) y se
mockean las funciones de app.gvm_manage, igual que test_gvm_manage.py
mockea gvm_query un nivel mas abajo."""
import os

import pytest
from fastapi.testclient import TestClient

import app.gvm_manage as gm
import app.main as m


@pytest.fixture
def client():
    def fake_claims():
        return {"sub": "tester", "org_id": "org1", "role": "admin"}

    m.app.dependency_overrides[m.get_current_claims] = fake_claims
    os.environ["GVM_USER"] = "admin"
    os.environ["GVM_PASSWORD"] = "pw"
    try:
        yield TestClient(m.app)
    finally:
        m.app.dependency_overrides.pop(m.get_current_claims, None)
        os.environ.pop("GVM_USER", None)
        os.environ.pop("GVM_PASSWORD", None)
        os.environ.pop("GVM_SOCKET_PATH", None)


@pytest.fixture
def patch_gvm_manage(monkeypatch):
    def _patch(**fakes):
        for name, fn in fakes.items():
            monkeypatch.setattr(gm, name, fn)
    return _patch


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
    async def fake_get_report_xml(socket_path, user, password, report_id):
        assert report_id == "rep1"
        return True, "<report/>", ""

    async def fake_export_report(socket_path, user, password, report_id, fmt):
        assert fmt == "pdf"
        return True, b"PDFDATA", "sentinelops-report-rep1.pdf", ""

    patch_gvm_manage(get_report_xml=fake_get_report_xml, export_report=fake_export_report)

    r = client.get("/openvas/reports/rep1")
    assert r.status_code == 200
    assert r.json()["raw_xml"] == "<report/>"

    r = client.get("/openvas/reports/rep1/export?format=pdf")
    assert r.status_code == 200
    assert r.content == b"PDFDATA"
    assert "attachment" in r.headers["content-disposition"]
    assert "sentinelops-report-rep1.pdf" in r.headers["content-disposition"]


def test_export_report_gvm_failure_is_502(client, patch_gvm_manage):
    async def fake_export_report(socket_path, user, password, report_id, fmt):
        return False, None, None, "formato no soportado"

    patch_gvm_manage(export_report=fake_export_report)
    r = client.get("/openvas/reports/rep1/export?format=docx")
    assert r.status_code == 502
