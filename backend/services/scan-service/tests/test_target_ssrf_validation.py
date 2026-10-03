"""Regression tests para la proteccion SSRF agregada en
app/target_validation.py::reject_dangerous_network_target y su conexion en
app/schemas.py -- ver el docstring de esa funcion para el alcance exacto
(nombres de servicio internos de la plataforma + metadata/link-local/
loopback/multicast/reserved, NUNCA rangos RFC1918, que son un target de
LAN legitimo para este producto)."""
import pytest
from pydantic import ValidationError

from app.target_validation import reject_dangerous_network_target, validate_target
from app.schemas import AgentScanJobCreate, ScanJobCreate, ScanScheduleCreate


# --- reject_dangerous_network_target: unidad ------------------------------

@pytest.mark.parametrize(
    "target",
    [
        "169.254.169.254",  # metadata de cloud (AWS/GCP/Azure)
        "169.254.0.0/16",  # CIDR explicito del mismo rango
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "::1",
        "postgres",
        "auth-service",
        "https://postgres:5432/",
        "redis:6379",
    ],
)
def test_rejects_internal_and_metadata_targets(target):
    with pytest.raises(ValueError):
        reject_dangerous_network_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.5",
        "10.0.0.0/24",
        "192.168.1.1",
        "192.168.0.0/16",
        "172.16.0.5",
        "example.com",
        "https://example.com:8443/",
    ],
)
def test_allows_lan_and_internet_targets(target):
    # No debe levantar -- escanear la LAN propia del cliente (RFC1918) o
    # un host de internet real sigue siendo el caso de uso principal.
    reject_dangerous_network_target(target)


# --- ScanJobCreate: aplicado segun scanner_type ----------------------------

def test_scan_job_create_rejects_metadata_target_for_nuclei():
    with pytest.raises(ValidationError):
        ScanJobCreate(scanner_type="nuclei", target="169.254.169.254")


def test_scan_job_create_rejects_internal_service_name_for_nuclei():
    with pytest.raises(ValidationError):
        ScanJobCreate(scanner_type="nuclei", target="http://auth-service:8000/")


def test_scan_job_create_allows_lan_target_for_nuclei():
    job = ScanJobCreate(scanner_type="nuclei", target="192.168.1.5")
    assert job.target == "192.168.1.5"


def test_scan_job_create_allows_trivy_image_named_like_internal_service():
    # "postgres:16" es una referencia de imagen de trivy legitima y comun
    # -- no debe confundirse con el contenedor "postgres" de la plataforma.
    job = ScanJobCreate(scanner_type="trivy", target="postgres:16")
    assert job.target == "postgres:16"


# --- ScanScheduleCreate: exento cuando hay agent_id ------------------------

def test_schedule_rejects_internal_target_without_agent():
    with pytest.raises(ValidationError):
        ScanScheduleCreate(scanner_type="nuclei", target="postgres", frequency="daily")


def test_schedule_allows_internal_looking_target_with_agent():
    # Un agente remoto corre fuera de la red docker de la plataforma, en la
    # LAN real del cliente -- el denylist de nombres de servicio internos
    # no tiene sentido ahi.
    schedule = ScanScheduleCreate(
        scanner_type="nuclei", target="postgres", frequency="daily",
        agent_id="agent-1", agent_api_key="k",
    )
    assert schedule.target == "postgres"


# --- AgentScanJobCreate: nunca se le aplica (corre en la LAN del cliente) -

def test_agent_scan_job_create_never_blocks_network_denylist():
    job = AgentScanJobCreate(agent_id="agent-1", scanner_type="nuclei", target="postgres", api_key="k")
    assert job.target == "postgres"


# --- validate_target: sin cambios de comportamiento (solo sintaxis) -------

def test_validate_target_still_rejects_flag_like_targets():
    with pytest.raises(ValueError):
        validate_target("--script=exploit")
