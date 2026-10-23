"""Chequeos del repo para la instalacion rapida (imagenes prearmadas, imagen base comun,
build en lotes). Corren en CI y en la PC del desarrollador; dentro del contenedor (donde no
estan los archivos del repo) se saltean."""
import fnmatch
import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[4]
DOCKERIGNORE = RAIZ / ".dockerignore"

pytestmark = pytest.mark.skipif(
    not (RAIZ / "docker-compose.yml").exists(),
    reason="los archivos del repo no estan disponibles (corriendo dentro de su contenedor)",
)


def _patrones_dockerignore():
    pats = []
    for linea in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if linea and not linea.startswith("#") and not linea.startswith("!"):
            pats.append(linea)
    return pats


def _ignorado(ruta: str, patrones) -> bool:
    """Aproximacion fiel para estos patrones: coincide con la ruta o con alguno de sus padres."""
    partes = ruta.split("/")
    candidatos = ["/".join(partes[: i + 1]) for i in range(len(partes))]
    for pat in patrones:
        pat = pat.rstrip("/")
        simple = pat[3:] if pat.startswith("**/") else pat
        for cand in candidatos:
            if fnmatch.fnmatch(cand, pat) or fnmatch.fnmatch(cand, simple):
                return True
            if "/" not in simple and fnmatch.fnmatch(cand.split("/")[-1], simple):
                return True
    return False


# --- Punto 6: .dockerignore ---------------------------------------------------------------
@pytest.mark.parametrize(
    "ruta",
    [
        ".git/config",
        "node_modules/x/index.js",
        "backend/services/auth-service/node_modules/x.js",
        ".env",
        "release/TERO.zip",
        "backup.zip",
        "paquete.tar.gz",
        "imagenes.tar.zst",
        "auditoria-seguridad/_snapshot.tgz",
        "backend/services/auth-service/__pycache__/a.pyc",
        "ci.yml.bak",
    ],
)
def test_dockerignore_excluye_lo_que_no_debe_viajar_al_daemon(ruta):
    assert _ignorado(ruta, _patrones_dockerignore()), f"{ruta} deberia estar en .dockerignore"


def _rutas_copiadas_por_los_dockerfiles():
    rutas = set()
    for df in list((RAIZ / "backend").glob("services/*/Dockerfile")) + [RAIZ / "backend" / "Dockerfile.base"]:
        if not df.exists():
            continue
        for linea in df.read_text(encoding="utf-8").splitlines():
            m = re.match(r"COPY\s+(?:--\S+\s+)*(backend/\S+)\s", linea)
            if m:
                rutas.add(m.group(1).rstrip("/"))
    return rutas


def test_dockerignore_no_excluye_nada_que_un_dockerfile_copie():
    pats = _patrones_dockerignore()
    rutas = _rutas_copiadas_por_los_dockerfiles()
    assert rutas, "no se encontro ningun COPY backend/... en los Dockerfiles"
    excluidas = sorted(r for r in rutas if _ignorado(r, pats))
    assert not excluidas, f".dockerignore excluye rutas que los Dockerfiles copian: {excluidas}"


def test_env_example_limita_la_compilacion_en_paralelo():
    texto = (RAIZ / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^COMPOSE_PARALLEL_LIMIT=[1-3]\s*$", texto, flags=re.M)


def test_makefile_apaga_attestations_y_limita_paralelismo():
    texto = (RAIZ / "Makefile").read_text(encoding="utf-8")
    assert "BUILDX_NO_DEFAULT_ATTESTATIONS" in texto
    assert "COMPOSE_PARALLEL_LIMIT" in texto
