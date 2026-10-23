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


# --- Punto 3: imagen base comun ------------------------------------------------------------
SIMPLES = [
    "auth", "asset", "vuln", "siem", "soar", "case", "purple", "report",
    "notification", "integration", "threatintel", "asm", "cloud",
]
PROPIOS = ["scan", "coderepo"]   # tienen herramientas propias: se quedan con su Dockerfile


def _pines(ruta: Path) -> dict:
    pines = {}
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        codigo = linea.split("#")[0].strip()
        if codigo:
            nombre = re.split(r"[=<>!~]", codigo)[0].lower()
            pines[nombre] = codigo
    return pines


def test_hay_13_servicios_simples_y_2_propios():
    assert len(SIMPLES) == 13
    for s in SIMPLES + PROPIOS:
        assert (RAIZ / "backend" / "services" / f"{s}-service" / "Dockerfile").exists()


@pytest.mark.parametrize("s", SIMPLES)
def test_servicio_simple_hereda_de_la_base(s):
    df = (RAIZ / "backend" / "services" / f"{s}-service" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^ARG BASE_IMAGE=tero-base$", df, flags=re.M)
    assert re.search(r"^FROM \$\{BASE_IMAGE\}$", df, flags=re.M)
    assert "pip install" in df and "apt-get" not in df, "lo comun ya viene en la base"
    assert re.search(r"^USER sentinelops$", df, flags=re.M)
    assert "HEALTHCHECK --start-period=90s" in df
    assert 'CMD ["uvicorn", "app.main:app"' in df


@pytest.mark.parametrize("s", PROPIOS)
def test_scan_y_coderepo_siguen_separados(s):
    df = (RAIZ / "backend" / "services" / f"{s}-service" / "Dockerfile").read_text(encoding="utf-8")
    assert "tero-base" not in df and "BASE_IMAGE" not in df


@pytest.mark.parametrize("s", SIMPLES)
def test_pines_de_la_base_coinciden_con_los_del_servicio(s):
    """Si un servicio pinea otra version que la base, pip la reinstalaria encima (imagen mas
    gorda) y el audit no veria lo que de verdad corre."""
    base = _pines(RAIZ / "backend" / "requirements-base.txt")
    servicio = _pines(RAIZ / "backend" / "services" / f"{s}-service" / "requirements.txt")
    distintos = {n: (base[n], servicio[n]) for n in base if n in servicio and base[n] != servicio[n]}
    assert not distintos, f"{s}-service pinea distinto que la base: {distintos}"


def test_la_base_instala_backend_shared_y_crea_el_usuario():
    df = (RAIZ / "backend" / "Dockerfile.base").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim" in df
    assert "COPY backend/shared ./backend/shared" in df
    assert "useradd" in df and "-u 1001" in df
    assert "USER " not in df.replace("USER sentinelops", ""), "la base no fija USER: lo hace cada servicio"


def _bloque(compose: str, nombre: str) -> str:
    m = re.search(rf"^  {re.escape(nombre)}:\n(.*?)(?=^  \S|\Z)", compose, flags=re.S | re.M)
    assert m, f"no hay servicio {nombre} en docker-compose.yml"
    return m.group(1)


def test_compose_construye_la_base_antes_que_los_servicios_simples():
    compose = (RAIZ / "docker-compose.yml").read_text(encoding="utf-8")
    base = _bloque(compose, "tero-base")
    assert "backend/Dockerfile.base" in base
    assert re.search(r'profiles:\s*\["build"\]', base), "la base no debe levantarse con `up`"
    for s in SIMPLES:
        b = _bloque(compose, f"{s}-service")
        assert re.search(r"additional_contexts:\s*\n\s+tero-base: service:tero-base", b), s
    for s in PROPIOS:
        assert "tero-base" not in _bloque(compose, f"{s}-service")
