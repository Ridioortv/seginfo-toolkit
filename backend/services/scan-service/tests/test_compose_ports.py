"""Postgres no debe publicarse en el host: choca con un PostgreSQL de la PC."""
import pytest


def test_postgres_is_not_published_on_the_host(tmp_path):
    """Regresion: publicar 127.0.0.1:5432 hacia fallar `docker compose up` con
    "address already in use" en cualquier PC que ya tuviera un PostgreSQL."""
    import re
    from pathlib import Path

    compose = Path(__file__).resolve().parents[4] / "docker-compose.yml"
    if not compose.exists():
        pytest.skip("docker-compose.yml no esta disponible (corriendo dentro de su contenedor)")
    text = compose.read_text(encoding="utf-8")
    match = re.search(r"^  postgres:\n(.*?)(?=^  \S|\Z)", text, flags=re.S | re.M)
    assert match, "no se encontro el servicio postgres en docker-compose.yml"
    block = "\n".join(line for line in match.group(1).splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"^\s+ports:", block, flags=re.M), "postgres no debe publicar puertos en el host"
    assert "5432:5432" not in block
