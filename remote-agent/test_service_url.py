"""Tests de la validacion de SCAN_SERVICE_URL del agente (solo http/https y
aviso si la key viajaria en claro hacia un host publico)."""
import pytest

import agent


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "gopher://h", "//sin-esquema", "http://"])
def test_rejects_non_http_urls(url):
    with pytest.raises(SystemExit) as exc:
        agent._check_service_url(url)
    assert exc.value.code == 2


@pytest.mark.parametrize("url", [
    "http://localhost:8003",
    "http://127.0.0.1:8003",
    "http://host.docker.internal:8003",
    "http://scan-service:8000",
    "http://192.168.1.10:8003",
    "http://10.0.0.5:8003",
    "https://agentes.empresa.com",
])
def test_accepts_without_warning(url, capsys):
    agent._check_service_url(url)
    assert "ADVERTENCIA" not in capsys.readouterr().err


def test_warns_on_cleartext_http_to_public_host(capsys):
    agent._check_service_url("http://8.8.8.8:8003")
    agent._check_service_url("http://agentes.empresa.com")
    assert capsys.readouterr().err.count("ADVERTENCIA") == 2
