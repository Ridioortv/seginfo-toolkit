"""GET /scan-images es solo lectura: el menu muestra "Imagenes y Paquetes" a todos
los roles, pero la API exigia admin/soc_manager/analyst y un viewer veia un 403
disfrazado de "No se pudo conectar con scan-service"."""
import pytest
from fastapi.testclient import TestClient

from app import main as scan_main
from app.dependencies import get_current_claims
from backend.shared.database import get_db


@pytest.fixture
def client(monkeypatch):
    async def fake_inventory(db, org_id):
        return []

    async def fake_db():
        yield None

    monkeypatch.setattr(scan_main.services, "get_image_inventory", fake_inventory)
    scan_main.app.dependency_overrides[get_db] = fake_db
    yield TestClient(scan_main.app, raise_server_exceptions=False)
    scan_main.app.dependency_overrides.clear()


@pytest.mark.parametrize("role", ["viewer", "analyst", "soc_manager", "admin"])
def test_every_role_can_read_the_image_inventory(client, role):
    scan_main.app.dependency_overrides[get_current_claims] = lambda: {"sub": "u", "role": role, "org_id": "o"}
    assert client.get("/scan-images").status_code == 200


def test_unauthenticated_is_rejected(client):
    assert client.get("/scan-images").status_code in (401, 403)
