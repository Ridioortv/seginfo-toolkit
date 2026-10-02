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


async def _spawn_compose_up() -> "asyncio.subprocess.Process":
    """Lanza `up -d` en SEGUNDO PLANO (no bloqueante), a diferencia de
    _run_compose (que espera a que termine). La primera vez este comando
    puede tardar varios minutos bajando las ~10 imagenes de
    registry.community.greenbone.net -- si lo esperaramos entero antes de
    arrancar a consultar `ps`, la barra de progreso queda congelada en el
    valor inicial todo ese tiempo, indistinguible de un cuelgue real
    (exactamente lo que reporto Manu: "se queda en 1% y no avanza"). Con
    esto corriendo de fondo, el loop de mas abajo puede consultar `ps` en
    paralelo y mostrar avance real apenas el primer contenedor (los que no
    dependen de una imagen pesada) queda arriba, sin esperar a que
    terminen de bajar TODAS las imagenes."""
    return await asyncio.create_subprocess_exec(
        "docker", "compose", "-p", COMPOSE_PROJECT_NAME, "--profile", "openvas", "up", "-d", *OPENVAS_SERVICES,
        cwd=COMPOSE_PROJECT_DIR,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


async def _drain_stream(stream, limit: int = 4000) -> str:
    """Lee el stdout/stderr combinado de `up -d` hasta que el proceso lo
    cierra. Hay que consumirlo si o si -- con suficiente salida (barras de
    progreso de `docker pull`, por ejemplo) un pipe sin leer se llena y el
    proceso queda trabado esperando que alguien lo vacie, lo que
    reintroduciria el mismo cuelgue que este cambio busca evitar. De paso,
    da contexto util para el mensaje de error si termina fallando.
    Devuelve como mucho los ultimos `limit` caracteres."""
    chunks: list[bytes] = []
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")[-limit:]


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


def _read_env_dict() -> dict[str, str]:
    """Lee el .env actual como diccionario -- usado por POST /start para
    reusar GVM_USER/GVM_PASSWORD ya guardados en vez de generar una
    password nueva en cada activacion (ver _reload_gvm_clients: ese era
    el bug de fondo detras de los fallos de autenticacion intermitentes
    de toda la sesion -- nada propagaba la password nueva a los
    contenedores ya corriendo)."""
    values: dict[str, str] = {}
    for line in _read_env_lines():
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line)
        if m:
            values[m.group(1)] = m.group(2).strip()
    return values


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


async def _reload_gvm_clients(timeout: int = 120) -> tuple[bool, str]:
    """Recrea gvm-agent para que arranque con el GVM_USER/GVM_PASSWORD que
    _write_env_vars acaba de escribir en .env -- a diferencia de
    scan-service (que se autocura solo, ver
    backend/services/scan-service/app/main.py::GET /openvas/auto-activate/progress),
    gvm-agent fija esas credenciales como `environment:` al crear el
    contenedor (ver docker-compose.yml) y NO las vuelve a leer despues:
    sin este paso quedaria con la password VIEJA hasta el proximo
    reinicio manual, que es exactamente el bug de fondo detras de los
    "Authentication failed" intermitentes de toda la sesion. remote-agent
    (Agente Docker) no usa credenciales GVM -> no hace falta tocarlo, y
    scan-service no se toca aca para no cortar el propio polling de
    progreso que esta usando este endpoint."""
    r = await asyncio.to_thread(
        _run_compose, "--profile", "openvas", "up", "-d", "--force-recreate", "gvm-agent",
        timeout=timeout,
    )
    if r.returncode == 0:
        return True, ""
    detail = (r.stderr or r.stdout or "error desconocido").strip()
    return False, detail[-1500:]


# Generoso sobre el tiempo que gvmd puede tardar en soltar el lock del feed
# si justo esta a mitad de su propio sync de SCAP/CVE (visto en vivo en esta
# sesion) -- preferible esperar de mas a que --rebuild-gvmd-data falle con
# "Feed locked." y deje todo a medio importar.
_GVMD_DATA_LOCK_TIMEOUT_SECONDS = 1800


async def _rebuild_gvmd_data() -> tuple[bool, str]:
    """Fuerza a gvmd a (re)importar scan configs/port lists/report formats
    desde el feed en disco -- sin esto, gvmd puede tener el feed de NVTs
    sincronizado y las imagenes/socket todos sanos y AUN ASI no tener
    ningun scan config real (visto en vivo en esta sesion: config_count=0
    pese a que los archivos del feed ya estaban en disco). Via CLI, no
    GMP, porque corre ANTES de que haya ningun usuario GMP para consultar.
    El timeout del subproceso queda apenas arriba de --feed-lock-timeout
    para que el propio gvmd devuelva su mensaje de "sigue bloqueado" en
    vez de que Python lo mate primero."""
    r = await asyncio.to_thread(
        _run_compose, "exec", "-T", "-u", "gvmd", "gvmd", "gvmd",
        "--rebuild-gvmd-data=all", f"--feed-lock-timeout={_GVMD_DATA_LOCK_TIMEOUT_SECONDS}",
        timeout=_GVMD_DATA_LOCK_TIMEOUT_SECONDS + 120,
    )
    if r.returncode == 0:
        return True, "scan configs/port lists/report formats importados desde el feed"
    detail = (r.stderr or r.stdout or "error desconocido").strip()
    return False, detail[-1500:]


# Cuenta los <config id="..."> de la respuesta GMP de <get_configs/> --
# ejecutado DENTRO de gvm-agent (ya tiene montado el socket de gvmd y,
# recien recreado por _reload_gvm_clients, las credenciales frescas como
# env vars) en vez de desde este contenedor (que no tiene gvm-cli ni el
# socket). Lee user/password/socket de os.environ, nunca de un argv --
# mismo criterio de no pasar secretos por linea de comando que el resto
# del repo. "--config ''" evita que gvm-cli intente leer
# ~/.config/gvm-tools.conf con HOME=/root heredado (ver
# remote-agent/agent.py::_ov_query, mismo problema).
_GET_CONFIG_COUNT_SCRIPT = """
import os, re, subprocess, sys
cmd = [
    'gvm-cli', '--config', '',
    '--gmp-username', os.environ.get('GVM_USER', ''),
    '--gmp-password', os.environ.get('GVM_PASSWORD', ''),
    'socket', '--socketpath', os.environ.get('GVM_SOCKET_PATH', '/run/gvmd/gvmd.sock'),
    '--xml', '<get_configs/>',
]
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
if proc.returncode != 0:
    print('ERROR:' + proc.stderr[-800:])
    sys.exit(1)
print('COUNT:' + str(len(re.findall(r'<config id=', proc.stdout))))
"""


async def _get_config_count(timeout: int = 30) -> tuple[int, str]:
    r = await asyncio.to_thread(
        _run_compose, "--profile", "openvas", "exec", "-T", "-u", "nobody", "gvm-agent",
        "python3", "-c", _GET_CONFIG_COUNT_SCRIPT,
        timeout=timeout,
    )
    out = (r.stdout or "").strip()
    if r.returncode != 0 or "ERROR:" in out:
        return -1, (r.stderr or out or "sin salida").strip()[-800:]
    m = re.search(r"COUNT:(\d+)", out)
    if not m:
        return -1, f"salida inesperada de gvm-cli: {out[-500:]}"
    return int(m.group(1)), ""


def _fail(message: str) -> None:
    _state.update(running=False, error=message, detail=message)


async def _run_activation(gvm_user: str, gvm_password: str, gvm_socket_path: str) -> None:
    try:
        _state.update(
            running=True, provisioned=False, error=None,
            phase="iniciando", percent=1,
            detail="Descargando imagenes y levantando contenedores de OpenVAS...",
            gvm_user=None, gvm_password=None, gvm_socket_path=gvm_socket_path,
        )
        # `up -d` se lanza en segundo plano (ver _spawn_compose_up) para
        # poder consultar `ps` EN PARALELO mientras corre, en vez de
        # esperarlo entero antes de arrancar a mirar progreso. Se listan
        # los 16 servicios por nombre en vez de confiar solo en --profile
        # openvas: sin nombres explicitos, `up -d` toma como objetivo TODO
        # el proyecto (los servicios sin profiles + los del profile
        # pedido) -- lo que en la practica hizo que Compose
        # recreara/reiniciara scan-service, frontend, remote-agent y este
        # mismo orquestador en medio de una activacion anterior (visto en
        # logs reales: este proceso se reiniciaba solo apenas despues de
        # un POST /start). Con la lista explicita, `up -d` solo puede
        # tocar estos 16 -- nunca al resto del stack.
        up_proc = await _spawn_compose_up()
        wait_task = asyncio.create_task(up_proc.wait())
        drain_task = asyncio.create_task(_drain_stream(up_proc.stdout))
        up_running = True

        deadline = time.monotonic() + _SYNC_TIMEOUT_SECONDS
        while True:
            if up_running and wait_task.done():
                up_running = False
                if wait_task.result() != 0:
                    tail = await drain_task
                    _fail(
                        "no se pudieron levantar los contenedores: "
                        f"{tail.strip() or 'sin salida capturada, revisa a mano con docker compose logs'}"
                    )
                    return

            ps = await asyncio.to_thread(
                _run_compose, "--profile", "openvas", "ps", "-a", "--format", "json", *OPENVAS_SERVICES, timeout=30,
            )
            if ps.returncode == 0:
                done, total, failed = _progress_from_ps(ps.stdout)
                if failed:
                    _fail(
                        f"estos contenedores fallaron: {', '.join(failed)} -- revisa a mano con "
                        f"'docker compose --profile openvas logs {failed[0]}'"
                    )
                    return
                detail = (
                    "Descargando imagenes de OpenVAS (puede tardar varios minutos la primera vez)..."
                    if done == 0 and up_running
                    else f"Contenedores listos: {done}/{total} (la primera vez puede tardar 20-40 min)"
                )
                _state.update(percent=_sync_percent(done, total), phase="sincronizando", detail=detail)
                if done >= total and not up_running:
                    break
            # Si `ps` fallo esta vuelta (poco probable) no actualizamos
            # percent -- se reintenta solo en la proxima vuelta del loop,
            # en vez de tirar el error al toque por un blip pasajero.

            if time.monotonic() >= deadline:
                if up_running:
                    up_proc.kill()
                _fail(
                    f"paso mas de {_SYNC_TIMEOUT_SECONDS // 60} min y todavia no termino de levantar/"
                    "sincronizar -- revisa a mano con 'docker compose --profile openvas ps'"
                )
                return
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

        _state.update(phase="creando_usuario", percent=88, detail=f"Creando/actualizando el usuario GVM '{gvm_user}'...")
        ok, detail_user = await _ensure_gvm_user(gvm_user, gvm_password)
        if not ok:
            _fail(f"no se pudo crear/actualizar el usuario GVM: {detail_user}")
            return

        _write_env_vars({
            "GVM_SOCKET_PATH": gvm_socket_path,
            "GVM_USER": gvm_user,
            "GVM_PASSWORD": gvm_password,
        })

        # A partir de aca es exactamente lo que este sesion tuvo que hacer
        # A MANO por PowerShell cada vez que algo se desincronizaba:
        # recargar los clientes GVM con la credencial nueva, forzar la
        # importacion de gvmd-data, y recien ahi confiar en que un scan
        # real tenga con que correr. El boton "Activar OpenVAS" ahora hace
        # las tres cosas solo, sin que el operador tenga que tocar una
        # terminal.
        _state.update(
            phase="recargando_credenciales", percent=92,
            detail="Reiniciando el agente GVM para que tome las credenciales nuevas...",
        )
        ok, detail_reload = await _reload_gvm_clients()
        if not ok:
            _fail(f"no se pudo reiniciar el agente GVM con las credenciales nuevas: {detail_reload}")
            return

        _state.update(
            phase="importando_datos", percent=95,
            detail=(
                "Importando scan configs/port lists/report formats del feed en gvmd "
                "(puede tardar varios minutos si el feed todavia esta sincronizando)..."
            ),
        )
        ok, detail_rebuild = await _rebuild_gvmd_data()
        if not ok:
            _fail(f"no se pudieron importar los datos de gvmd (scan configs/port lists): {detail_rebuild}")
            return

        _state.update(
            phase="verificando", percent=98,
            detail="Verificando que gvmd tenga scan configs reales antes de dar todo por listo...",
        )
        config_count, detail_count = await _get_config_count()
        if config_count <= 0:
            extra = f" (detalle: {detail_count})" if detail_count else ""
            _fail(
                f"gvmd sigue sin scan configs reales despues de importar el feed{extra} -- revisa a mano con "
                "'docker compose --profile openvas exec -u gvmd gvmd gvmd --rebuild-gvmd-data=all'"
            )
            return

        _state.update(
            running=False, provisioned=True, error=None,
            phase="listo", percent=100,
            detail=(
                f"OpenVAS listo -- {detail_user}, {config_count} scan config(s) disponibles. "
                "Credenciales guardadas en .env."
            ),
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
        # Reusa lo que ya haya en .env ANTES de caer en "admin"/una password
        # al azar -- generar una password nueva en cada click (el
        # comportamiento viejo) es lo que de fondo causaba los
        # "Authentication failed" intermitentes de toda la sesion: nada
        # propagaba esa password nueva a gvm-agent/remote-agent, que seguian
        # corriendo con la vieja. Con esto, apretar "Activar OpenVAS" de
        # nuevo sobre una instalacion que ya funciona es idempotente.
        env_values = _read_env_dict()
        gvm_user = (
            (payload.get("gvm_user") or "").strip()
            or env_values.get("GVM_USER", "").strip()
            or "admin"
        )
        gvm_password = (
            (payload.get("gvm_password") or "").strip()
            or env_values.get("GVM_PASSWORD", "").strip()
            or secrets.token_urlsafe(18)
        )
        gvm_socket_path = (
            (payload.get("gvm_socket_path") or "").strip()
            or env_values.get("GVM_SOCKET_PATH", "").strip()
            or "/run/gvmd/gvmd.sock"
        )
        asyncio.create_task(_run_activation(gvm_user, gvm_password, gvm_socket_path))
        # Refleja el arranque al toque -- la corrida real recien va a
        # actualizar _state despues del primer await de adentro.
        _state.update(running=True, provisioned=False, error=None, phase="iniciando", percent=1,
                       detail="Levantando contenedores de OpenVAS...")
        return _state
