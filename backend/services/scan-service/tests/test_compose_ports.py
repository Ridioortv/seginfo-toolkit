"""Los servicios internos (Postgres, Redis, OpenSearch) no deben publicarse en el host:
chocan con un servicio de la PC o con un TERO anterior que siga prendido."""
import re
from pathlib import Path

import pytest

COMPOSE = Path(__file__).resolve().parents[4] / "docker-compose.yml"


def _service_block(text: str, name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text, flags=re.S | re.M)
    assert match, f"no se encontro el servicio {name} en docker-compose.yml"
    return "\n".join(line for line in match.group(1).splitlines() if not line.lstrip().startswith("#"))


@pytest.mark.parametrize(
    "service,port",
    [("postgres", "5432"), ("redis", "6379"), ("opensearch", "9200")],
)
def test_internal_services_are_not_published_on_the_host(service, port):
    """Regresion: publicar 127.0.0.1:5432 / :6379 / :9200 hacia fallar `docker compose up` con
    "address already in use" / "port is already allocated" si la PC (o un TERO anterior) ya usaba
    ese puerto. Los servicios los alcanzan por la red interna de Docker."""
    if not COMPOSE.exists():
        pytest.skip("docker-compose.yml no esta disponible (corriendo dentro de su contenedor)")
    block = _service_block(COMPOSE.read_text(encoding="utf-8"), service)
    assert not re.search(r"^\s+ports:", block, flags=re.M), f"{service} no debe publicar puertos en el host"
    assert f"{port}:{port}" not in block


def test_only_the_panel_and_the_apis_are_published():
    """Solo el frontend (5173) y las APIs (8001-8015) quedan publicados en la PC."""
    if not COMPOSE.exists():
        pytest.skip("docker-compose.yml no esta disponible (corriendo dentro de su contenedor)")
    text = COMPOSE.read_text(encoding="utf-8")
    published = re.findall(r'^\s+- "\$\{BIND_ADDR:-127\.0\.0\.1\}:(\d+):\d+"', text, flags=re.M)
    assert sorted(map(int, published)) == sorted([5173, *range(8001, 8016)])
    assert not re.search(r'^\s+- "127\.0\.0\.1:\d+:\d+"', text, flags=re.M)
