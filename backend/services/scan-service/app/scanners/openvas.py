"""Driver de OpenVAS/GVM: escaneo real de vulnerabilidades via Greenbone
Vulnerability Management (protocolo GMP), en modo deteccion (el motor
openvas-scanner/ospd-openvas corre NVTs de deteccion, nunca payloads de
explotacion activa).

Requiere el stack de GVM (gvmd + ospd-openvas + su propia base de datos y
feed de NVTs, ver docker-compose.yml seccion "OpenVAS/GVM") accesible via
el socket unix de gvmd, y credenciales GMP (GVM_USER/GVM_PASSWORD, ver
.env.example -- se crean con el comando de bootstrap documentado en
README.md/STATUS.md). Si el binario gvm-cli no esta instalado o no hay
credenciales configuradas, el driver reporta 'scanner_unavailable' /
un error claro en vez de fallar silenciosamente.

Flujo GMP real (a diferencia de la version anterior de este driver, que
solo hacia una consulta `get_vulns` sin autenticar y sin disparar ningun
escaneo):
  1. Descubre dinamicamente scanner_id / config_id / port_list_id via
     get_scanners / get_configs / get_port_lists, en vez de hardcodear
     UUIDs "bien conocidos" -- esos UUIDs pueden faltar en instalaciones
     nuevas o de arquitectura dividida (ospd-openvas) como esta (ver
     https://github.com/admirito/gvm-containers/issues/60).
  2. create_target -> create_task -> start_task.
  3. Poll de get_tasks hasta que el status sea terminal (Done/Stopped/
     Interrupted) o se agote GVM_SCAN_TIMEOUT_SECONDS.
  4. get_results del task para traer los hallazgos.
"""
import asyncio
import os
import pwd
import shutil
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape
from app.scanners.base import ScannerDriver, ScanResult


def _xml_attr(value: str) -> str:
    """Escapa `value` para insertarlo en un atributo XML delimitado por
    comillas SIMPLES (`id='...'`, el estilo que usa todo este archivo) --
    a diferencia de _xml_escape (pensado para texto plano entre tags, ej.
    <name>...</name>, donde una comilla simple no rompe nada), un atributo
    asi SI necesita escapar la comilla simple: sin esto, cualquiera de los
    ids que llegan aca sin validar contra un formato fijo (overrides de
    ScanJobCreate/ScanScheduleCreate.options como gvm_config_id/
    gvm_scanner_id/gvm_port_list_id/gvm_target_id/gvm_ssh_credential_id/
    gvm_smb_credential_id -- ver OpenVasDriver.run mas abajo -- y, en
    app/gvm_manage.py, credential_id/target_id/task_id/report_id tomados
    directo de un path param de la URL) podia cortar el atributo con una
    comilla simple e inyectar CUALQUIER comando GMP adicional en la misma
    sesion ya autenticada contra gvmd (crear/borrar usuarios, leer
    reportes de otra organizacion, lo que sea que GMP permita) -- un bug
    real encontrado al trazar de punta a punta de donde viene cada string
    que termina interpolado en un atributo de esta forma."""
    return _xml_escape(value, {"'": "&apos;"})

_SEVERITY_THRESHOLDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)

# Preferencias de nombre para el descubrimiento dinamico (en orden). Si
# ninguna preferencia matchea, se usa el primer item devuelto por gvmd --
# mejor un escaneo con la config/scanner/port_list "que sea" que fallar
# el job por completo.
_CONFIG_NAME_PREFERENCES = ("full and fast",)
_SCANNER_NAME_PREFERENCES = ("openvas default", "openvas")
_PORT_LIST_NAME_PREFERENCES = ("all iana assigned tcp and udp", "all iana assigned tcp", "all tcp")

_TERMINAL_TASK_STATUSES = {"Done", "Stopped", "Interrupted"}
_DEFAULT_POLL_INTERVAL = 15
_DEFAULT_SCAN_TIMEOUT = int(os.getenv("GVM_SCAN_TIMEOUT_SECONDS", "1500"))


def _severity_from_cvss(cvss: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if cvss >= threshold:
            return label
    return "info"


def _gvm_cmd(socket_path: str, user: str, password: str, xml: str) -> list[str]:
    """Funcion pura: construye el comando gvm-cli. Las credenciales van
    como flags globales -- gvm-cli se autentica solo, sin necesidad de
    mandar un <authenticate/> manual.

    "--config ''" es querido, no un accidente: por default gvm-cli busca
    un archivo de config en ~/.config/gvm-tools.conf (ver
    gvmtools/parser.py::DEFAULT_CONFIG_PATH), y "~" se expande con la
    variable de entorno HOME -- que en este subproceso sigue siendo
    /root (el HOME del proceso padre, que SI corre como root) aunque
    _drop_priv_to_nobody le baje los privilegios a "nobody" antes del
    exec (bajar privilegios con setuid/setgid no toca el entorno). Con
    HOME=/root, gvm-cli (ya como "nobody") intenta revisar si
    /root/.config/gvm-tools.conf existe y explota con PermissionError (no
    tiene permiso para ni siquiera mirar adentro de /root) -- error real,
    encontrado corriendo esto contra un gvmd real por primera vez.
    Pasar un config vacio hace que gvm-cli ni intente tocar el filesystem
    para esto (ver CliParser._load_config: "if not configfile: return
    config", corta antes de llegar a esa parte)."""
    return [
        "gvm-cli", "--config", "", "--gmp-username", user, "--gmp-password", password,
        "socket", "--socketpath", socket_path, "--xml", xml,
    ]


def _drop_priv_to_nobody() -> None:
    """preexec_fn para bajar privilegios del subproceso gvm-cli ANTES del
    exec (corre en el hijo, entre fork y exec). gvm-tools (el paquete pip
    que provee gvm-cli) se niega EXPLICITAMENTE a correr como root (ver
    gvmtools/helper.py::do_not_run_as_root, `raise RuntimeError("This
    tool MUST NOT be run as root user.")`) -- una proteccion de la
    libreria en si, sin ningun flag/env var para saltearla. Este
    contenedor si corre como root (necesario para nada en particular hoy,
    pero cambiar el usuario de TODO el proceso rompería los permisos de
    escritura de los caches de trivy/nuclei bajo /root -- ver Dockerfile),
    asi que en vez de eso le bajamos los privilegios SOLO a este
    subproceso puntual, usando "nobody" (uid/gid ya presentes en la
    imagen base, sin tener que crear un usuario nuevo).

    Si el socket de gvmd no fuera legible/escribible para "nobody" (un
    "Permission denied" en la salida de gvm-cli, en vez del error de
    "MUST NOT be run as root"), esa seria la siguiente pista: habria que
    ajustar los permisos del socket del lado de gvmd o compartir un
    grupo/uid especifico en vez de "nobody" generico."""
    nobody = pwd.getpwnam("nobody")
    os.setgroups([])
    os.setgid(nobody.pw_gid)
    os.setuid(nobody.pw_uid)


async def _spawn_gvm_cli(cmd: list[str]) -> asyncio.subprocess.Process:
    """Unico lugar que efectivamente lanza el subproceso gvm-cli -- tanto
    gvm_query como probe_connection pasan por aca para no duplicar el
    preexec_fn de mas arriba en dos lugares."""
    return await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        preexec_fn=_drop_priv_to_nobody,
    )


async def gvm_query(socket_path: str, user: str, password: str, xml: str, timeout: int = 60) -> tuple[int, str, str]:
    """Ejecuta un comando GMP contra gvmd via gvm-cli y devuelve
    (returncode, stdout, stderr). Antes vivia como closure local de
    OpenVasDriver.run -- se saco a nivel de modulo para que
    app/gvm_manage.py (configs/credenciales/targets/reportes del
    dashboard de OpenVAS, que necesita hablar el mismo protocolo GMP pero
    fuera del flujo de "correr un escaneo") pueda reusarla sin duplicar el
    manejo de timeout/cancelacion."""
    cmd = _gvm_cmd(socket_path, user, password, xml)
    proc = None
    try:
        proc = await _spawn_gvm_cli(cmd)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except FileNotFoundError:
        return -1, "", "gvm-cli no esta instalado en este contenedor"
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                # El proceso ya termino/fue cosechado por el event loop
                # justo en la ventana entre el timeout y este kill() --
                # race benigna de asyncio+uvloop con subprocesos (uvloop,
                # a diferencia del event loop por default de asyncio, NO
                # la absorbe silenciosamente). No es un error real: no hay
                # nada que matar porque el proceso ya no existe.
                pass
            await proc.wait()
        return -1, "", f"timeout ({timeout}s) hablando con gvmd"
    except asyncio.CancelledError:
        # Ver nmap.py: mata el gvm-cli que estaba esperando en vez de
        # dejarlo huerfano. Quien llama decide que hacer del lado de gvmd
        # (ver OpenVasDriver.run: best-effort stop_task si ya hay un task
        # creado).
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                # Misma race benigna que en el except TimeoutError de
                # arriba -- el proceso ya se fue solo.
                pass
            await proc.wait()
        raise
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _find_id_by_name(xml_text: str, item_tag: str, preferences: tuple[str, ...]) -> str | None:
    """Busca en una respuesta get_configs/get_scanners/get_port_lists el id
    del item cuyo <name> matchea (case-insensitive, substring) alguna de
    las preferencias en orden; si ninguna matchea, devuelve el primer id
    disponible. None si la lista viene vacia o el XML es invalido."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    items = []
    for item in root.findall(f".//{item_tag}"):
        item_id = item.get("id")
        name_el = item.find("name")
        name = name_el.text if name_el is not None and name_el.text else ""
        if item_id:
            items.append((item_id, name))

    if not items:
        return None

    for pref in preferences:
        for item_id, name in items:
            if pref in name.lower():
                return item_id

    return items[0][0]


def _parse_response_id(xml_text: str) -> str | None:
    """Los *_response de gvm-cli (create_target_response, create_task_response)
    traen el id del recurso creado como atributo del elemento raiz."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    return root.get("id") or None


def _response_status_ok(xml_text: str) -> bool:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    status = root.get("status") or ""
    return status.startswith("2")


def _build_create_target_xml(
    name: str,
    hosts: str,
    port_list_id: str,
    ssh_credential_id: str | None = None,
    smb_credential_id: str | None = None,
    alive_tests: str = "Consider Alive",
) -> str:
    """ssh_credential_id/smb_credential_id son opcionales -- sin ellos, el
    target queda igual que antes (escaneo SIN autenticar, solo deteccion
    de red). Con ellos, gvmd usa esas credenciales para loguearse al host
    durante el escaneo (ver create_credential en app/gvm_manage.py) y
    detectar mucho mas (vulnerabilidades locales, no solo expuestas por
    red) -- lo que GVM llama "escaneo autenticado".

    alive_tests="Consider Alive" (default, en vez de dejar que gvmd use su
    default propio -- "Scan Config Default", que combina ICMP+ARP Ping)
    salta POR COMPLETO la fase de deteccion de host-vivo de gvmd/ospd-
    openvas: esa fase manda pings ICMP y/o ARP crudos (sockets raw,
    broadcast), que NO atraviesan el NAT de Docker Desktop (Windows/Mac) --
    el mismo motivo documentado en remote-agent/README.md para nmap, y por
    el que el escaneo TCP interno de remote-agent/agent.py usa connect()
    en vez de pings. El trafico de los NVTs de deteccion real que corren
    DESPUES (la mayoria via conexiones TCP/UDP normales, ruteadas, no raw)
    SI puede atravesar ese NAT -- asi que "Consider Alive" es lo que deja
    pasar un escaneo real contra un target de LAN sin necesitar una
    maquina aparte con visibilidad de red nativa. Costo: si el host esta
    realmente apagado/inalcanzable, el escaneo tarda lo mismo que contra
    uno vivo en vez de saltarlo rapido -- aceptable dado el objetivo
    (poder escanear LAN desde el mismo Docker Desktop del operador)."""
    extra = f"<alive_tests>{_xml_escape(alive_tests)}</alive_tests>" if alive_tests else ""
    if ssh_credential_id:
        extra += f"<ssh_lsc_credential id='{_xml_attr(ssh_credential_id)}'/>"
    if smb_credential_id:
        extra += f"<smb_lsc_credential id='{_xml_attr(smb_credential_id)}'/>"
    return (
        f"<create_target><name>{_xml_escape(name)}</name>"
        f"<hosts>{_xml_escape(hosts)}</hosts>"
        f"<port_list id='{_xml_attr(port_list_id)}'/>{extra}</create_target>"
    )


def _build_create_task_xml(name: str, target_id: str, config_id: str, scanner_id: str) -> str:
    return (
        f"<create_task><name>{_xml_escape(name)}</name>"
        f"<target id='{_xml_attr(target_id)}'/><config id='{_xml_attr(config_id)}'/>"
        f"<scanner id='{_xml_attr(scanner_id)}'/></create_task>"
    )


def _parse_task_status(xml_text: str) -> tuple[str, int] | None:
    """Parsea la respuesta de get_tasks (con un solo <task/>, filtrado por
    id) y devuelve (status, progress). None si no se pudo parsear."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    task = root.find(".//task")
    if task is None:
        return None
    status_el = task.find("status")
    progress_el = task.find("progress")
    status = status_el.text if status_el is not None and status_el.text else "Unknown"
    try:
        progress = int(progress_el.text) if progress_el is not None and progress_el.text else 0
    except ValueError:
        progress = 0
    return status, progress


def _parse_gmp_results(xml_text: str) -> list[dict]:
    """Parsea una respuesta get_results (findall .//result) a la forma
    comun de findings del proyecto."""
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for result in root.findall(".//result"):
        name_el = result.find("name")
        severity_el = result.find("severity")
        host_el = result.find("host")
        port_el = result.find("port")
        desc_el = result.find("description")
        nvt_el = result.find("nvt")
        cve_el = nvt_el.find("cve") if nvt_el is not None else None
        try:
            cvss = float(severity_el.text) if severity_el is not None and severity_el.text else 0.0
        except ValueError:
            cvss = 0.0
        host = host_el.text if host_el is not None and host_el.text else ""
        findings.append(
            {
                "title": name_el.text if name_el is not None and name_el.text else "hallazgo OpenVAS",
                "description": (desc_el.text or "")[:1000] if desc_el is not None else "",
                "severity": _severity_from_cvss(cvss),
                "cve_id": cve_el.text if cve_el is not None and cve_el.text and cve_el.text != "NOCVE" else None,
                "service": f"{host}:{port_el.text}" if port_el is not None and port_el.text else host or None,
            }
        )
    return findings


async def probe_connection(socket_path: str, user: str, password: str, timeout: int = 20) -> tuple[bool, str]:
    """Prueba liviana de conectividad GMP (un solo <get_version/>, sin crear
    ningun target/task) para el boton "Activar OpenVAS" del frontend y para
    GET /openvas/status -- confirma que gvmd esta arriba y que las
    credenciales son validas ANTES de aplicarlas, en vez de que el usuario
    se entere recien cuando lanza el primer escaneo real."""
    if not shutil.which("gvm-cli"):
        return False, "gvm-cli no esta instalado en este contenedor (falta el paquete gvm-tools)"

    cmd = _gvm_cmd(socket_path, user, password, "<get_version/>")
    proc = None
    try:
        proc = await _spawn_gvm_cli(cmd)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except FileNotFoundError:
        return False, "gvm-cli no esta instalado en este contenedor"
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                # El proceso ya termino/fue cosechado justo entre el
                # timeout y este kill() -- race benigna de asyncio+uvloop
                # con subprocesos (ver gvm_query mas arriba, mismo patron).
                # Sin este guard, GET /openvas/status explotaba con un
                # ProcessLookupError sin manejar (500) cada vez que gvmd
                # respondia justo al borde del timeout, dejando
                # openvasReady en false para siempre del lado del
                # frontend -- "Activar OpenVAS" no cargaba y el scanner
                # nunca aparecia en los dropdowns de Escaneos programados/
                # remotos.
                pass
            await proc.wait()
        return False, (
            f"no hubo respuesta de gvmd en {timeout}s -- revisa que los contenedores del profile "
            "openvas esten arriba (docker compose --profile openvas ps) y que ya terminaron de "
            "sincronizar los feeds la primera vez (puede tardar 20-40 min)"
        )

    out = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    if proc.returncode != 0 or not _response_status_ok(out):
        detail = err.strip() or out.strip() or f"codigo de salida {proc.returncode}"
        return False, f"gvmd rechazo la conexion: {detail[:500]}"
    return True, "conectado a gvmd correctamente"


class OpenVasDriver(ScannerDriver):
    binary_name = "gvm-cli"

    async def run(self, target: str, options: dict) -> ScanResult:
        if not self.is_available():
            return ScanResult(
                raw_output="",
                error="gvm-cli no esta disponible en este contenedor (falta el paquete gvm-tools). "
                "El job queda marcado como scanner_unavailable.",
            )

        socket_path = options.get("gvm_socket") or os.getenv("GVM_SOCKET_PATH") or "/run/gvmd/gvmd.sock"
        user = options.get("gvm_user") or os.getenv("GVM_USER") or ""
        password = options.get("gvm_password") or os.getenv("GVM_PASSWORD") or ""
        if not user or not password:
            return ScanResult(
                raw_output="",
                error="OpenVAS esta APAGADO por defecto en esta instalacion (el motor Greenbone/GVM "
                "no esta levantado, o faltan GVM_USER/GVM_PASSWORD en .env). Para activarlo segui "
                "openvas/LEEME.md -- en resumen: openvas/Encender-OpenVAS.ps1 y luego "
                "openvas/Configurar-OpenVAS.ps1. Mientras tanto, usa nmap / nuclei / trivy.",
            )

        async def q(xml: str, timeout: int = 60) -> tuple[int, str, str]:
            return await gvm_query(socket_path, user, password, xml, timeout)

        # El dashboard de OpenVAS (app/gvm_manage.py + endpoints /openvas/*
        # en main.py) deja elegir a mano el config/scanner/port_list y las
        # credenciales de escaneo autenticado, y guarda targets reusables
        # en gvmd -- estos overrides opcionales son como esas elecciones
        # llegan hasta aca. Sin ninguno (el caso de siempre: un escaneo
        # "rapido" desde la pantalla generica de Escaneos), el compor-
        # tamiento es EXACTAMENTE el de antes: auto-descubrir todo y crear
        # un target nuevo sin autenticar.
        override_target_id = (options.get("gvm_target_id") or "").strip() or None
        override_config_id = (options.get("gvm_config_id") or "").strip() or None
        override_scanner_id = (options.get("gvm_scanner_id") or "").strip() or None
        override_port_list_id = (options.get("gvm_port_list_id") or "").strip() or None
        override_ssh_credential_id = (options.get("gvm_ssh_credential_id") or "").strip() or None
        override_smb_credential_id = (options.get("gvm_smb_credential_id") or "").strip() or None
        # Ver el docstring de _build_create_target_xml: default "Consider
        # Alive" para que el escaneo no dependa de ICMP/ARP (no atraviesan
        # el NAT de Docker Desktop). Dejar pasar un override explicito por
        # si algun dia esto corre en una maquina con visibilidad de red
        # nativa (ver remote-agent/openvas-agent/) donde SI conviene el
        # default de gvmd (salta hosts caidos mas rapido).
        override_alive_tests = (options.get("gvm_alive_tests") or "").strip() or "Consider Alive"

        # task_id se completa en el paso 2 -- se declara antes del try para
        # que el except CancelledError de mas abajo sepa si ya existe un
        # task GVM real corriendo (y haya que pedirle stop_task) o si la
        # cancelacion llego antes de crear ninguno. Tambien se usa para
        # "marcar" el ScanResult final con el id de task GVM (ver _tag mas
        # abajo), asi el dashboard puede pedir despues el reporte
        # completo/exportarlo sin tener que re-buscarlo por nombre.
        task_id: str | None = None

        def _tag(result: ScanResult) -> ScanResult:
            if task_id:
                result.gvm_task_id = task_id
            return result

        try:
            # -- 1. Descubrimiento dinamico de config/scanner (siempre
            # hacen falta, con o sin target guardado) ------------------------
            if override_config_id:
                config_id = override_config_id
            else:
                rc, out, err = await q("<get_configs/>")
                if rc != 0:
                    return ScanResult(raw_output=out, error=f"no se pudo consultar get_configs: {err[:1000]}")
                config_id = _find_id_by_name(out, "config", _CONFIG_NAME_PREFERENCES)

            if override_scanner_id:
                scanner_id = override_scanner_id
            else:
                rc, out, err = await q("<get_scanners/>")
                if rc != 0:
                    return ScanResult(raw_output=out, error=f"no se pudo consultar get_scanners: {err[:1000]}")
                scanner_id = _find_id_by_name(out, "scanner", _SCANNER_NAME_PREFERENCES)

            # port_list solo hace falta si hay que CREAR un target nuevo --
            # un target guardado (override_target_id) ya trae el suyo.
            port_list_id: str | None = None
            if not override_target_id:
                if override_port_list_id:
                    port_list_id = override_port_list_id
                else:
                    rc, out, err = await q("<get_port_lists/>")
                    if rc != 0:
                        return ScanResult(raw_output=out, error=f"no se pudo consultar get_port_lists: {err[:1000]}")
                    port_list_id = _find_id_by_name(out, "port_list", _PORT_LIST_NAME_PREFERENCES)

            if not (config_id and scanner_id and (override_target_id or port_list_id)):
                return ScanResult(
                    raw_output="",
                    error=(
                        "gvmd no tiene configuradas las entidades minimas para escanear "
                        f"(config={config_id}, scanner={scanner_id}, port_list={port_list_id}). "
                        "Puede que el feed de NVTs todavia no termino de sincronizar la primera vez "
                        "-- ver README.md/STATUS.md sobre el tiempo de sincronizacion inicial."
                    ),
                )

            # -- 2. target: reusar uno guardado o crear uno nuevo ------------
            task_name = f"sentinelops-{target}-{int(time.time())}"
            if override_target_id:
                target_id = override_target_id
            else:
                rc, out, err = await q(
                    _build_create_target_xml(
                        task_name, target, port_list_id, override_ssh_credential_id, override_smb_credential_id,
                        override_alive_tests,
                    )
                )
                if rc != 0 or not _response_status_ok(out):
                    return ScanResult(raw_output=out, error=f"no se pudo crear el target GVM: {err[:1000] or out[:1000]}")
                target_id = _parse_response_id(out)
                if not target_id:
                    return ScanResult(raw_output=out, error="create_target no devolvio un id de target")

            # -- 3. create_task / start_task ----------------------------------
            rc, out, err = await q(_build_create_task_xml(task_name, target_id, config_id, scanner_id))
            if rc != 0 or not _response_status_ok(out):
                return ScanResult(raw_output=out, error=f"no se pudo crear el task GVM: {err[:1000] or out[:1000]}")
            task_id = _parse_response_id(out)
            if not task_id:
                return ScanResult(raw_output=out, error="create_task no devolvio un id de task")

            rc, out, err = await q(f"<start_task task_id='{_xml_attr(task_id)}'/>")
            if rc != 0:
                return _tag(ScanResult(raw_output=out, error=f"no se pudo iniciar el task GVM: {err[:1000]}"))

            # -- 4. Poll hasta terminal o timeout ----------------------------
            deadline = time.monotonic() + _DEFAULT_SCAN_TIMEOUT
            last_status, last_progress = "Requested", 0
            while time.monotonic() < deadline:
                await asyncio.sleep(_DEFAULT_POLL_INTERVAL)
                rc, out, err = await q(f"<get_tasks task_id='{_xml_attr(task_id)}'/>")
                if rc != 0:
                    continue  # error transitorio consultando estado -- reintenta en el proximo ciclo
                parsed = _parse_task_status(out)
                if parsed is None:
                    continue
                last_status, last_progress = parsed
                if last_status in _TERMINAL_TASK_STATUSES:
                    break
            else:
                return _tag(ScanResult(
                    raw_output="",
                    error=(
                        f"timeout esperando que termine el escaneo GVM ({_DEFAULT_SCAN_TIMEOUT}s, "
                        f"ultimo estado visto: {last_status} {last_progress}%). El escaneo puede seguir "
                        "corriendo en gvmd -- subir GVM_SCAN_TIMEOUT_SECONDS si el target es grande."
                    ),
                ))

            if last_status != "Done":
                return _tag(ScanResult(raw_output="", error=f"el escaneo GVM termino en estado '{last_status}', no 'Done'"))

            # -- 5. get_results -----------------------------------------------
            rc, out, err = await q(f"<get_results task_id='{_xml_attr(task_id)}' filter='rows=1000'/>", timeout=120)
            if rc != 0:
                return _tag(ScanResult(raw_output=out, error=f"no se pudieron obtener los resultados: {err[:1000]}"))

            return _tag(ScanResult(raw_output=out, findings=_parse_gmp_results(out)))
        except asyncio.CancelledError:
            # A diferencia de nmap/trivy/nuclei (un solo subproceso local
            # nuestro), aca el escaneo real lo corre gvmd/ospd-openvas del
            # otro lado del socket -- matar el gvm-cli que estaba esperando
            # (ya lo hizo gvm_query arriba) NO detiene ese escaneo remoto.
            # Si ya se llego a crear un task GVM, se le pide stop_task
            # best-effort antes de propagar la cancelacion, para no dejar
            # un escaneo real corriendo en gvmd huerfano de un job que en
            # nuestra DB ya va a quedar 'cancelled'. Nunca debe tapar el
            # CancelledError original: cualquier error de esta limpieza
            # solo se ignora.
            if task_id:
                try:
                    await q(f"<stop_task task_id='{_xml_attr(task_id)}'/>", timeout=15)
                except Exception:  # noqa: BLE001 -- best-effort
                    pass
            raise
