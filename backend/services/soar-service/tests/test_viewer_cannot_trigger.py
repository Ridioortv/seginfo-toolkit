from fastapi.testclient import TestClient

import app.main as m
from backend.shared.security import create_access_token


def test_viewer_cannot_trigger_playbooks():
    token = create_access_token("u@example.com", "viewer", org_id="org-1")
    r = TestClient(m.app).post("/trigger", json={}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
