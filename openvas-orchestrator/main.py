"""openvas-orchestrator: el UNICO servicio de SentinelOps con acceso al
socket de Docker (ver Dockerfile y docker-compose.yml). Su unico trabajo
es levantar el profile "openvas" (~16 contenedores, ver docker-compose.yml)
y crear/actualizar el usuario GVM cuando scan-service se lo pide (boton
"Probar y activar" en la UI) -- asi el operador no tiene que correr los
scripts de PowerShell (openvas/Encender-OpenVAS.ps1 y
Configurar-OpenVAS.ps1) a mano; ambos caminos siguen siendo validos, este
solo automatiza el mismo procedimiento.

Superficie de ataque acotada A PROPOSITO: sin puerto publicado en
docker-compose.yml (solo alcanzable desde dentro de la red de Compose, y
en la practica solo lo llama scan-service), sin autenticacion propia (el
limite de confianza es la red interna, igual que ya confian entre si
gvmd/ospd-openvas), y con exactamente 2 acciones fijas -- arrancar el
profile openvas + reportar progreso -- nunca un comando arbitrario que
venga de afuera. Tiene el socket de Docker (equivalente a control total
del host Docker), asi que cualquier cambio a este archivo hay que pensarlo
con esa vara.

Estado en memoria (variable global `_state`) a proposito: un solo
operador, una sola activacion posible a la vez, sin necesidad de
persistencia -- si este proceso se reinicia a mitad de una sincronizacion
de feeds, los contenedores de GVM siguen corriendo igual (docker no los
para), y un nuevo POST /start simplemente retoma el poll desde donde esten
(`docker compose up -d` es idempotente: no reinicia lo que ya esta arriba)."""
import asyncio
import json
import os
import re
import secrets
import subprocess
import time
from fastapi import FastAPI

app = FastAPI(title="SentinelOps OpenVAS Orchestrator", version="0.1.0")

COMPOSE_PROJECT_NAME = os.getenv("COMPOSE_PROJECT_NAME", "seginfo-toolkit")
COMPOSE_PROJECT_DIR = os.getenv("COMPOSE_PROJECT_DIR", "/workspace")
ENV_PATH = os.path.join(COMPOSE_PROJECT_DIR, ".env")

# Los 16 servicios del profile "openvas" (ver docker-compose.yml) -- se
# usan para calcular el porcentaje de progreso (cuantos ya estan
# "listos") sin tener que reimplementar el grafo de dependencias que
# Compose ya resuelve solo al hacer `up -d`.
OPENVAS_SERVICES = [
    "pg-gvm-migrator", "pg-gvm", "gvm-redis",
    "vulnerability-tests", "notus-data", "scap-data", "cert-bund-data",
    "dfn-cert-data", "data-objects", "report-formats", "gpg-data",
    "gvmd", "configure-openvas", "openvas", "openvasd", "ospd-openvas",
]

# Generoso sobre los 20-40 min documentados (ver openvas/LEEME.md) para no
# cortar de mas en una PC lenta o una conexion mala para bajar los feeds.
_SYNC_TIMEOUT_SECONDS = 50 * 60
_POLL_INTERVAL_SECONDS = 10

_state: dict = {
    "running": False,
    "provisioned": False,
    "phase": "inactivo",
    "percent": 0,
    "detail": "",
    "error": None,
    "gvm_user": None,
    "gvm_password": None,
    "gvm_socket_path": None,
}
_lock = asyncio.Lock()


def _run_compose(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT_NAME, *args],
        cwd=COMPOSE_PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _parse_compose_ps_json(stdout: str) -> list[dict]:
    """`docker compose ps --format json` devuelve un unico array JSON en
    algunas versiones de Compose v2 y un objeto JSON por linea (JSONL) en
    otras -- se soportan las dos en vez de asumir una."""
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass
    entries = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _classify_container(entry: dict) -> str:
    """'done' | 'failed' | 'pending' para un contenedor del profile
    openvas. No todos exponen healthcheck (Health queda "" si no lo
    tienen) -- en ese caso alcanza con que este 'running'. Separado de
    _progress_from_ps para poder testearlo con entradas sueltas, sin
    tener que armar un ps -a completo."""
    state = (entry.get("State") or "").lower()
    health = (entry.get("Health") or "").lower()
    exit_raw = entry.get("ExitCode")
    try:
        exit_code = int(exit_raw) if exit_raw not in (None, "") else None
    except (TypeError, ValueError):
        exit_code = None

    if state == "exited":
        return "done" if exit_code == 0 else "failed"
    if health == "unhealthy":
        return "failed"
    if health == "healthy":
        return "done"
    if not health and state == "running":
        return "done"
    return "pending"


def _progress_from_ps(stdout: str) -> tuple[int, int, list[str]]:
    """(done_count, total, servicios_fallados) sobre OPENVAS_SERVICES,
    leyendo la salida de `docker compose ps -a --format json`. Funcion
    pura (aparte de _run_compose) para poder testearla con un stdout
    fabricado, sin Docker real."""
    entries = _parse_compose_ps_json(stdout)
    by_service = {e.get("Service"): e for e in entries if e.get("Service")}
    done = 0
    failed = []
    for name in OPENVAS_SERVICES:
        entry = by_service.get(name)
        if entry is None:
            continue  # todavia ni se creo el contenedor -- sigue "pending"
        status = _classify_container(entry)
        if status == "done":
            done += 1
        elif status == "failed":
            failed.append(name)
    return done, len(OPENVAS_SERVICES), failed


def _sync_percent(done: int, total: int) -> int:
    """5% apenas se lanza `up -d`, hasta 90% cuando todos los servicios
    del profile estan listos -- el ultimo tramo (90-100%) es crear el
    usuario GVM, que no forma parte de este calculo."""
    if total == 0:
        return 5
    return min(90, 5 + round(85 * done / total))


def _read_env_lines() -> list[str]:
    if not os.path.exists(ENV_PATH):
        return []
    with open(ENV_PATH, "r", encoding="utf-8") as fh:
        return fh.read().splitlines()


def _render_env_lines(lines: list[str], values: dict[str, str]) -> list[str]:
    """Reemplaza in-place las claves de `values` que ya existen en `lines`
    y agrega al final las que falten -- mismo criterio que
    openvas/Configurar-OpenVAS.ps1::Set-EnvVar, reescrito aca para que el
    camino automatico deje el .env exactamente como lo dejaria el manual.
    Funcion pura para poder testearla sin tocar un archivo real."""
    seen = set()
    out = []
    for line in lines:
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) in values:
            out.append(f"{m.group(1)}={values[m.group(1)]}")
            seen.add(m.group(1))
        else:
            out.append(line)
    for key, value in values.items():
        if key not in seen:
            out.append(f"{key}={value}")
    return out


def _write_env_vars(values: dict[str, str]) -> None:
    lines = _render_env_lines(_read_env_lines(), values)
    with open(ENV_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


async def _ensure_gvm_user(user: str, password: str) -> tuple[bool, str]:
    """Crea el usuario GVM; si ya existe (create-user falla), le resetea
    la password -- mismo fallback de dos pasos que
    openvas/Configurar-OpenVAS.ps1."""
    r = await asyncio.to_thread(
        _run_compose, "exec", "-T", "-u", "gvmd", "gvmd", "gvmd",
        f"--create-user={user}", f"--password={password}",
        timeout=30,
    )
    if r.returncode == 0:
        return True, "usuario creado"
    r2 = await asyncio.to_thread(
        _run_compose, "exec", "-T", "-u", "gvmd", "gvmd", "gvmd",
        f"--user={user}", f"--new-password={password}",
        timeout=30,
    )
    if r2.returncode == 0:
        return True, "password actualizada (el usuario ya existia)"
    detail = (r2.stderr or r.stderr or "error desconocido").strip()
    return False, detail[-1500:]


def _fail(message: str) -> None:
    _state.update(running=False, error=message, detail=message)


async def _run_activation(gvm_user: str, gvm_password: str, gvm_socket_path: str) -> None:
    try:
        _state.update(
            running=True, provisioned=False, error=None,
            phase="iniciando", percent=1, detail="Levantando contenedores de OpenVAS...",
            gvm_user=None, gvm_password=None, gvm_socket_path=gvm_socket_path,
        )
        # IMPORTANTE: se listan los 16 servicios por nombre en vez de
        # confiar solo en --profile openvas. Sin nombres explicitos, `up
        # -d` toma como objetivo TODO el proyecto (los servicios sin
        # profiles + los del profile pedido) -- lo que en la practica
        # hizo que Compose recreara/reiniciara scan-service, frontend,
        # remote-agent y este mismo orquestador en medio de la activacion
        # (visto en logs: este proceso se reiniciaba solo apenas despues
        # de un POST /start). Con la lista explicita, `up -d` solo puede
        # tocar estos 16 -- nunca al resto del stack.
        up = await asyncio.to_thread(
            _run_compose, "--profile", "openvas", "up", "-d", *OPENVAS_SERVICES, timeout=180,
        )
        if up.returncode != 0:
            _fail(f"no se pudieron levantar los contenedores: {up.stderr.strip()[-1500:]}")
            return

        _state.update(phase="sincronizando", percent=5, detail=(
            "Contenedores iniciados, sincronizando feeds "
            "(la primera vez tarda 20-40 minutos)..."
        ))
        deadline = time.monotonic() + _SYNC_TIMEOUT_SECONDS
        while True:
            ps = await asyncio.to_thread(
                _run_compose, "--profile", "openvas", "ps", "-a", "--format", "json", *OPENVAS_SERVICES, timeout=30,
            )
            if ps.returncode != 0:
                _fail(f"no se pudo consultar el estado de los contenedores: {ps.stderr.strip()[-1500:]}")
                return
            done, total, failed = _progress_from_ps(ps.stdout)
            if failed:
                _fail(
                    f"estos contenedores fallaron: {', '.join(failed)} -- revisa a mano con "
                    f"'docker compose --profile openvas logs {failed[0]}'"
                )
                return
            _state.update(
                percent=_sync_percent(done, total),
                detail=f"Contenedores listos: {done}/{total} (la primera vez puede tardar 20-40 min)",
            )
            if done >= total:
                break
            if time.monotonic() >= deadline:
                _fail(
                    f"paso mas de {_SYNC_TIMEOUT_SECONDS // 60} min y todavia no terminaron de "
                    "sincronizar los feeds -- revisa a mano con 'docker compose --profile openvas ps'"
                )
                return
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

        _state.update(phase="creando_usuario", percent=92, detail=f"Creando/actualizando el usuario GVM '{gvm_user}'...")
        ok, detail = await _ensure_gvm_user(gvm_user, gvm_password)
        if not ok:
            _fail(f"no se pudo crear/actualizar el usuario GVM: {detail}")
            return

        _write_env_vars({
            "GVM_SOCKET_PATH": gvm_socket_path,
            "GVM_USER": gvm_user,
            "GVM_PASSWORD": gvm_password,
        })

        _state.update(
            running=False, provisioned=True, error=None,
            phase="listo", percent=100,
            detail=f"OpenVAS listo -- {detail}. Credenciales guardadas en .env.",
            gvm_user=gvm_user, gvm_password=gvm_password, gvm_socket_path=gvm_socket_path,
        )
    except subprocess.TimeoutExpired as exc:
        _fail(f"timeout ejecutando '{' '.join(exc.cmd)}'")
    except Exception as exc:  # noqa: BLE001 -- nunca dejar la tarea de fondo morir en silencio
        _fail(f"error inesperado: {exc}")


@app.get("/status")
async def get_status():
    return _state


@app.post("/start")
async def start(payload: dict):
    async with _lock:
        if _state["running"]:
            return _state
        gvm_user = (payload.get("gvm_user") or "admin").strip() or "admin"
        gvm_password = (payload.get("gvm_password") or "").strip() or secrets.token_urlsafe(18)
        gvm_socket_path = (payload.get("gvm_socket_path") or "").strip() or "/run/gvmd/gvmd.sock"
        asyncio.create_task(_run_activation(gvm_user, gvm_password, gvm_socket_path))
        # Refleja el arranque al toque -- la corrida real recien va a
        # actualizar _state despues del primer await de adentro.
        _state.update(running=True, provisioned=False, error=None, phase="iniciando", percent=1,
                       detail="Levantando contenedores de OpenVAS...")
        return _state
