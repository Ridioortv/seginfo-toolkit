"""Los Dockerfiles no deben consultar la API de GitHub ("latest") al compilar.

La API rechaza las consultas anonimas desde la integracion continua (KeyError 'tag_name') y la
publicacion de imagenes fallaba al azar. Las versiones van fijas y verificadas con sha256.
"""
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[4]


def _dockerfiles():
    return [p for p in (RAIZ / "backend").rglob("Dockerfile*") if p.is_file()]


def test_ningun_dockerfile_usa_la_api_de_github():
    assert _dockerfiles(), "no se encontraron Dockerfiles"
    malos = [str(p.relative_to(RAIZ)) for p in _dockerfiles() if "api.github.com" in p.read_text(encoding="utf-8")]
    assert not malos, f"consultan api.github.com al compilar: {malos}"


def test_scan_service_fija_nuclei_y_zap_con_sha256():
    txt = (RAIZ / "backend/services/scan-service/Dockerfile").read_text(encoding="utf-8")
    assert "ARG NUCLEI_VERSION=" in txt
    assert "ARG ZAP_VERSION=" in txt and "ARG ZAP_SHA256=" in txt
    assert txt.count("sha256sum -c") >= 3  # trivy, nuclei, zap
