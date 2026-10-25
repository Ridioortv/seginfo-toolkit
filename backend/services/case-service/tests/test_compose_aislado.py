"""docker-compose.aislado.yml: todos los servicios de TERO entran en modo aislado y la red no traduce direcciones."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[4]
BASE, OVERRIDE = ROOT / "docker-compose.yml", ROOT / "docker-compose.aislado.yml"


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture()
def compose():
    if not (BASE.exists() and OVERRIDE.exists()):
        pytest.skip("los compose no estan disponibles (corriendo dentro de su contenedor)")
    return _load(BASE), _load(OVERRIDE)


def test_every_backend_service_is_isolated(compose):
    base, over = compose
    backend = {n for n, s in base["services"].items() if "-service" in n and not n.startswith("remote-agent")}
    assert backend <= set(over["services"])
    for name in backend:
        env = over["services"][name]["environment"]
        assert env["TERO_ISOLATED_MODE"] == "1", name
        assert "TERO_EGRESS_ALLOW" in env, name


def test_network_has_no_masquerade_and_scan_keeps_a_lan_path(compose):
    _base, over = compose
    opts = over["networks"]["default"]["driver_opts"]
    assert opts["com.docker.network.bridge.enable_ip_masquerade"] == "false"
    assert set(over["services"]["scan-service"]["networks"]) == {"default", "escaneo"}
    assert over["networks"]["escaneo"] == {}
    # y la pantalla lo informa: la excepcion esta declarada
    assert over["services"]["case-service"]["environment"]["TERO_NETWORK_EXCEPTIONS"] == "scan-service"


def test_expected_services_match_compose(compose):
    from app.egress_catalog import EXPECTED_SERVICES
    base, _over = compose
    backend = {n for n in base["services"] if n.endswith("-service")}
    assert set(EXPECTED_SERVICES) == backend
