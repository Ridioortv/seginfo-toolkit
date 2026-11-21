"""Trivy se instala con version fija y checksum verificado (no con el script install.sh de la
rama main, que consulta GitHub por la "ultima" version y fallo en la integracion continua)."""
from pathlib import Path

import pytest

SERVICES = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("servicio", ["scan-service", "coderepo-service"])
def test_trivy_con_version_fija_y_checksum(servicio):
    texto = (SERVICES / servicio / "Dockerfile").read_text(encoding="utf-8")
    assert "contrib/install.sh" not in texto
    assert "ARG TRIVY_VERSION=" in texto
    assert "sha256sum -c" in texto
