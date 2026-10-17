"""Las acciones de contencion (bloquear IP, aislar host, crear ticket) las
dispara soar-service con un JWT de servicio (rol admin). Un viewer no."""
import pytest
from fastapi.testclient import TestClient

import app.main as m
from backend.shared.security import create_access_token


def _auth(role):
    return {"Authorization": "Bearer " + create_access_token("u@example.com", role, org_id="org-1")}


@pytest.mark.parametrize("path,body", [
    ("/internal/actions/block-ip", {"ip": "1.2.3.4"}),
    ("/internal/actions/isolate-host", {"hostname": "h1"}),
    ("/internal/actions/create-ticket", {"title": "t", "description": "d"}),
])
def test_viewer_gets_403_on_internal_actions(path, body):
    client = TestClient(m.app)
    assert client.post(path, json=body, headers=_auth("viewer")).status_code == 403
