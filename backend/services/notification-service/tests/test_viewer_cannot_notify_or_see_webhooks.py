"""Un usuario viewer no debe poder disparar notificaciones reales ni ver el
webhook completo de los canales (equivale a una credencial)."""
import datetime

import pytest
from fastapi.testclient import TestClient

import app.main as m
import app.services as svc
from backend.shared.security import create_access_token


class _FakeDb:
    async def commit(self):
        pass


async def _fake_get_db():
    yield _FakeDb()


def _auth(role):
    return {"Authorization": "Bearer " + create_access_token("u@example.com", role, org_id="org-1")}


@pytest.fixture
def client():
    m.app.dependency_overrides[m.get_db] = _fake_get_db
    yield TestClient(m.app)
    m.app.dependency_overrides.clear()


def test_viewer_cannot_use_internal_notify(client):
    r = client.post("/internal/notify", json={"subject": "s", "body": "b"}, headers=_auth("viewer"))
    assert r.status_code == 403


class _Chan:
    def __init__(self):
        self.id = "c1"
        self.name = "slack"
        self.channel_type = "slack"
        self.config = {"webhook_url": "https://hooks.slack.com/services/T000/B000/SECRETSECRET"}
        self.enabled = True
        self.created_at = datetime.datetime(2026, 1, 1)


def test_redact_channel_config_hides_webhook_path_and_keeps_recipient():
    out = svc.redact_channel_config({"webhook_url": "https://hooks.slack.com/services/T/B/SECRET", "smtp_to": "a@b.com", "token": "x"})
    assert "SECRET" not in str(out)
    assert out["webhook_url"].startswith("https://hooks.slack.com/")
    assert out["smtp_to"] == "a@b.com"
    assert out["token"] != "x"


def test_channels_list_redacted_for_viewer_but_full_for_admin(client, monkeypatch):
    async def fake_list(db, org):
        return [_Chan()]

    monkeypatch.setattr(svc, "list_channels", fake_list)
    viewer = client.get("/channels", headers=_auth("viewer")).json()
    assert "SECRETSECRET" not in str(viewer)
    admin = client.get("/channels", headers=_auth("admin")).json()
    assert "SECRETSECRET" in str(admin)
