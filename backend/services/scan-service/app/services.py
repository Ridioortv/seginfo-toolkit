"""Business logic for scan-service: orquestacion de jobs de escaneo
DEFENSIVOS (solo deteccion) y reenvio de hallazgos normalizados a
vuln-service para priorizacion (CVSS/EPSS/KEV)."""
import asyncio
import shutil
import json
import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
import httpx
from sqlalchemy import select, or_, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import ScanJob, ScanStatus, ScanSchedule, ScanAgent, AgentScanJob, ScannerType
from app.scanners import get_driver, DRIVERS

logger = configure_logging("scan-service")

VULN_SERVICE_URL = os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000")
SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _run_refresh_cmd(cmd: list[str], label: str, timeout: int) -> None:
    """Corre un comando de refresco de datos de escaner (DB de trivy,
    templates de nuclei) en segundo plano. Nunca levanta excepcion --
    un refresh fallido (red caida, binario ausente en un entorno de test,
    etc.) solo se loguea, no debe tumbar el scheduler ni el servicio."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            logger.warning(
                f"{label}: fallo (codigo {proc.returncode})",
                extra={"stderr": stderr.decode(errors="replace")[:500]},
            )
        else:
            logger.info(f"{label}: ok")
    except FileNotFoundError:
        logger.warning(f"{label}: binario no encontrado en este contenedor, se omite")
    except asyncio.TimeoutError:
        logger.warning(f"{label}: timeout ({timeout}s)")
    except Exception as exc:  # noqa: BLE001 -- nunca debe tumbar el scheduler
        logger.warning(f"{label}: error inesperado: {exc}")


async def refresh_trivy_db() -> None:
    """Refresca la base de datos de CVEs de trivy en segundo plano. Se
    registra como job periodico de APScheduler (ver app/main.py) para que
    cada escaneo individual pueda correr con --skip-db-update (ver
    app/scanners/trivy.py) sin quedar con una DB eternamente vieja."""
    from app.scanners.trivy import TRIVY_CACHE_DIR

    await _run_refresh_cmd(
        ["trivy", "image", "--download-db-only", "--cache-dir", TRIVY_CACHE_DIR],
        "refresh_trivy_db",
        timeout=600,
    )


async def refresh_nuclei_templates() -> None:
    """Refresca las plantillas de nuclei en segundo plano (ver
    app/scanners/nuclei.py, que corre con -duc para no pagar este costo
    en cada escaneo individual)."""
    await _run_refresh_cmd(
        ["nuclei", "-update-templates", "-silent"],
        "refresh_nuclei_templates",
        timeout=300,
    )


async def create_uploaded_scan_job(db: AsyncSession, display_name: str, actor: str, organization_id: str) -> ScanJob:
    """Crea el ScanJob de un archivo subido y lo devuelve AL TOQUE -- la
    corrida real de trivy (execute_uploaded_scan_job, mas abajo) se dispara
    aparte via BackgroundTasks, igual que create_scan_job/execute_scan_job
    para escaneos normales por target.

    Antes esta funcion hacia todo de una: corria trivy DENTRO del mismo
    request/response del upload (podia tardar hasta 9 min, ver el timeout
    de mas abajo). Con un archivo grande o una imagen con muchas capas, el
    request quedaba abierto minutos enteros -- el navegador (u otra cosa
    de por medio) lo podia cortar antes de que trivy terminara, y eso se
    veia en el frontend como "Sin respuesta (Network Error) -- el
    contenedor probablemente no esta corriendo", que no tenia nada que ver
    con la causa real (trivy seguia corriendo tranquilo del otro lado)."""
    lower = display_name.lower()
    modo = "imagen" if lower.endswith((".tar", ".tar.gz", ".tgz")) else "paquetes"
    job = ScanJob(
        organization_id=organization_id,
        name=f"trivy ({modo}): {display_name}"[:255],
        scanner_type=ScannerType.trivy,
        target=display_name[:500],
        options={"mode": "upload"},
        created_by=actor,
        status=ScanStatus.pending,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)
    return job


async def execute_uploaded_scan_job(session_factory, job_id: str, file_path: str, tmpdir: str) -> None:
    """Corre trivy sobre el archivo subido (ver create_uploaded_scan_job) en
    background -- mismo patron de auto-registro/cancelacion que
    execute_scan_job, pero sin pasar por un driver de app/scanners/ porque
    el comando cambia segun si es una imagen .tar o un manifiesto de
    paquetes. Borra tmpdir al final pase lo que pase (completado, fallado,
    cancelado) para no dejar el archivo subido tirado en disco."""
    from app.scanners.trivy import _parse_trivy_json, _parse_trivy_packages, TRIVY_CACHE_DIR
    task = asyncio.current_task()
    if task is not None:
        register_running_scan(job_id, task)
    try:
        async with session_factory() as db:
            job = await db.get(ScanJob, job_id)
            if job is None:
                return
            if job.status == ScanStatus.cancelled:
                # Ver el mismo chequeo en execute_scan_job -- sin esto, un
                # archivo cancelado mientras todavia estaba "pending" se
                # terminaba escaneando igual, pisando el estado cancelado.
                return
            job.status = ScanStatus.running
            job.started_at = _now()
            await db.commit()

            lower = job.target.lower()
            if lower.endswith((".tar", ".tar.gz", ".tgz")):
                cmd = ["trivy", "image", "--input", file_path]
            else:
                cmd = ["trivy", "fs", file_path]
            cmd += ["--format", "json", "--quiet", "--timeout", "8m", "--cache-dir", TRIVY_CACHE_DIR,
                    "--skip-db-update", "--skip-java-db-update", "--list-all-pkgs"]

            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=540)
            except FileNotFoundError:
                job = await db.get(ScanJob, job_id)
                job.status = ScanStatus.scanner_unavailable
                job.error_message = "trivy no esta disponible en este contenedor"
                job.finished_at = _now()
                await db.commit()
                return
            except asyncio.TimeoutError:
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                job = await db.get(ScanJob, job_id)
                job.status = ScanStatus.failed
                job.error_message = "timeout de escaneo (540s)"
                job.finished_at = _now()
                await db.commit()
                return

            raw = stdout.decode(errors="replace")
            job = await db.get(ScanJob, job_id)
            job.raw_result = raw[:200_000]
            job.finished_at = _now()
            if proc.returncode not in (0, 1):
                job.status = ScanStatus.failed
                job.error_message = (stderr.decode(errors="replace")[:2000]
                                     or f"trivy salio con codigo {proc.returncode}")
            else:
                job.findings = _parse_trivy_json(raw)
                job.packages = _parse_trivy_packages(raw)
                job.status = ScanStatus.completed
            await db.commit()
            if job.status == ScanStatus.completed and job.findings:
                await _forward_findings_to_vuln_service(job)
                await _forward_findings_to_siem_service(job)
    except asyncio.CancelledError:
        async with session_factory() as db:
            job = await db.get(ScanJob, job_id)
            if job is not None and is_cancellable_status(job.status):
                job.status = ScanStatus.cancelled
                job.error_message = "Cancelado por el usuario"
                job.finished_at = _now()
                await db.commit()
        logger.info("scan de archivo subido cancelado", extra={"job_id": job_id})
    finally:
        unregister_running_scan(job_id)
        shutil.rmtree(tmpdir, ignore_errors=True)


def build_image_inventory(jobs: list) -> list[dict]:
    """Logica pura (sin DB) de get_image_inventory: agrupa una lista de
    ScanJob de trivy ya COMPLETADOS por `target` y se queda con el
    inventario de paquetes del mas reciente (asi reescanear una imagen
    actualiza su inventario en vez de duplicarlo). Se separa de la query
    de DB para poder testearla con instancias de ScanJob armadas a mano
    (sin sesion/base real), igual de aislado que is_cancellable_status y
    el resto de las reglas de negocio de este archivo.

    Asume que `jobs` ya viene ordenado por finished_at DESCENDENTE (mas
    reciente primero) -- asi el primer job que aparece para cada target
    es el que gana. Solo entran los jobs con `packages`: un trivy
    escaneado ANTES de que existiera --list-all-pkgs (ver trivy.py) tiene
    findings pero packages vacio, y no aporta nada nuevo a este
    inventario."""
    by_target: dict[str, object] = {}
    for job in jobs:
        if not job.packages:
            continue
        if job.target not in by_target:
            by_target[job.target] = job

    images = []
    for target, job in by_target.items():
        vuln_count_by_severity: dict[str, int] = {}
        for finding in job.findings or []:
            sev = finding.get("severity", "info")
            vuln_count_by_severity[sev] = vuln_count_by_severity.get(sev, 0) + 1
        images.append(
            {
                "target": target,
                "scan_job_id": job.id,
                "scanned_at": job.finished_at,
                "mode": (job.options or {}).get("mode", "image"),
                "package_count": len(job.packages),
                "vulnerability_count": len(job.findings or []),
                "vulnerabilities_by_severity": vuln_count_by_severity,
                "packages": job.packages,
            }
        )
    images.sort(key=lambda i: i["scanned_at"] or _now(), reverse=True)
    return images


async def get_image_inventory(db: AsyncSession, organization_id: str, limit_scans: int = 500) -> list[dict]:
    """Dashboard de imagenes/paquetes -- ver build_image_inventory para la
    logica de agrupacion en si."""
    result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.organization_id == organization_id,
            ScanJob.scanner_type == ScannerType.trivy,
            ScanJob.status == ScanStatus.completed,
        )
        .order_by(ScanJob.finished_at.desc())
        .limit(limit_scans)
    )
    return build_image_inventory(result.scalars().all())


async def create_scan_job(db: AsyncSession, payload, actor: str, organization_id: str) -> ScanJob:
    job = ScanJob(
        organization_id=organization_id,
        name=payload.name,
        scanner_type=payload.scanner_type,
        target=payload.target,
        asset_id=payload.asset_id,
        options=payload.options,
        created_by=actor,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)
    return job


async def list_scan_jobs(
    db: AsyncSession, organization_id: str, status_filter: str | None = None, scanner_type: str | None = None
) -> list[ScanJob]:
    query = select(ScanJob).where(ScanJob.organization_id == organization_id)
    if status_filter:
        query = query.where(ScanJob.status == status_filter)
    if scanner_type:
        query = query.where(ScanJob.scanner_type == scanner_type)
    result = await db.execute(query.order_by(ScanJob.created_at.desc()))
    return list(result.scalars().all())


async def get_scan_job(db: AsyncSession, job_id: str, organization_id: str) -> ScanJob | None:
    job = await db.get(ScanJob, job_id)
    if job is None or job.organization_id != organization_id:
        return None
    return job


TERMINAL_SCAN_STATUSES = {"completed", "failed", "scanner_unavailable", "cancelled"}
CANCELLABLE_SCAN_STATUSES = {"pending", "running"}


def is_deletable_status(status_value) -> bool:
    """Un escaneo (propio o de agente remoto) solo se puede borrar una vez
    terminado -- pending/running todavia pueden estar corriendo en
    background_tasks o esperando el proximo polling del agente."""
    value = status_value.value if hasattr(status_value, "value") else status_value
    return value in TERMINAL_SCAN_STATUSES


def is_cancellable_status(status_value) -> bool:
    """Solo tiene sentido cancelar un escaneo que todavia no llego a un
    estado terminal -- uno completed/failed/scanner_unavailable/cancelled ya
    no tiene nada corriendo que cancelar."""
    value = status_value.value if hasattr(status_value, "value") else status_value
    return value in CANCELLABLE_SCAN_STATUSES


def is_running_status(status_value) -> bool:
    """True solo si el escaneo esta corriendo AHORA (tiene un background task
    vivo en este proceso). Se usa para no borrar un escaneo por debajo de su
    propia tarea. pending y los estados terminales SI se pueden borrar."""
    value = status_value.value if hasattr(status_value, "value") else status_value
    return value == "running"


# --- Cancelacion de escaneos en curso ---
# Diccionario en memoria (job_id -> asyncio.Task) de los escaneos que estan
# corriendo AHORA en este mismo proceso de scan-service. Alcanza con que sea
# en memoria (no en la DB) porque solo tiene sentido cancelar un escaneo
# mientras el proceso que lo esta corriendo sigue vivo: si el contenedor se
# reinicio, cualquier job que haya quedado "running" en la DB ya esta
# huerfano de todas formas (nadie lo esta corriendo), y cancel_scan_job mas
# abajo lo detecta (no hay tarea registrada) y lo marca cancelado
# directamente sin necesidad de matar nada. Un solo dict de proceso alcanza
# porque scan-service corre como una sola instancia -- mismo supuesto que ya
# usa el scheduler de ScanSchedule (ver app/main.py).
_RUNNING_SCAN_TASKS: dict[str, "asyncio.Task"] = {}


def register_running_scan(job_id: str, task: "asyncio.Task") -> None:
    _RUNNING_SCAN_TASKS[job_id] = task


def unregister_running_scan(job_id: str) -> None:
    _RUNNING_SCAN_TASKS.pop(job_id, None)


def cancel_running_scan(job_id: str) -> bool:
    """Pide la cancelacion del escaneo si esta corriendo en ESTE proceso
    (via Task.cancel() -- ver execute_scan_job, que atrapa el
    CancelledError resultante para matar el subproceso del driver y dejar
    el job en estado 'cancelled' en vez de dejarlo colgado). Devuelve False
    si no hay ninguna tarea viva registrada para ese job_id (ya termino, o
    quedo huerfana de un reinicio del contenedor) -- en ese caso quien
    llama tiene que marcar el estado 'cancelled' a mano, no hay nada que
    matar."""
    task = _RUNNING_SCAN_TASKS.get(job_id)
    if task is None or task.done():
        return False
    task.cancel()
    return True


async def cancel_scan_job(db: AsyncSession, job: ScanJob) -> ScanJob:
    """Cancela un escaneo pending/running (ver is_cancellable_status, que ya
    se valido en el endpoint antes de llamar aca). Si hay una tarea viva
    corriendo este job en este proceso, le pide la cancelacion -- el propio
    execute_scan_job termina de escribir el estado final cuando el
    CancelledError le llega. Si no hay ninguna tarea viva (job huerfano de
    un reinicio del contenedor, o todavia no llego a registrarse), se marca
    cancelado aca mismo porque no hay nada corriendo que vaya a hacerlo."""
    if not cancel_running_scan(job.id):
        job.status = ScanStatus.cancelled
        job.error_message = "Cancelado por el usuario"
        job.finished_at = _now()
        await db.flush()
    return job


async def delete_scan_job(db: AsyncSession, job: ScanJob) -> None:
    """Solo se borran escaneos ya terminados (completed/failed/scanner_unavailable) --
    uno en pending/running todavia puede estar corriendo en background_tasks."""
    await db.delete(job)
    await db.flush()


def scanners_status() -> dict:
    return {scanner_type.value: driver.is_available() for scanner_type, driver in DRIVERS.items()}


async def create_schedule(db: AsyncSession, payload, actor: str, organization_id: str) -> ScanSchedule:
    # payload.agent_id ya se valido en main.py::create_schedule (agente
    # existe + api key correcta) antes de llegar aca -- esta funcion solo
    # persiste la decision, nunca la key (ver ScanScheduleCreate.agent_api_key).
    schedule = ScanSchedule(
        organization_id=organization_id,
        name=payload.name,
        scanner_type=payload.scanner_type,
        target=payload.target,
        options=payload.options,
        frequency=payload.frequency,
        hour=payload.hour,
        minute=payload.minute,
        day_of_week=payload.day_of_week,
        agent_id=payload.agent_id,
        created_by=actor,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


async def list_schedules(db: AsyncSession, organization_id: str | None = None) -> list[ScanSchedule]:
    """organization_id opcional SOLO para el uso interno del lifespan
    (re-registrar los jobs de TODAS las organizaciones al arrancar el
    scheduler en proceso) -- todo endpoint HTTP siempre lo pasa."""
    query = select(ScanSchedule)
    if organization_id is not None:
        query = query.where(ScanSchedule.organization_id == organization_id)
    result = await db.execute(query.order_by(ScanSchedule.created_at.desc()))
    return list(result.scalars().all())


async def get_schedule(db: AsyncSession, schedule_id: str, organization_id: str) -> ScanSchedule | None:
    schedule = await db.get(ScanSchedule, schedule_id)
    if schedule is None or schedule.organization_id != organization_id:
        return None
    return schedule


async def set_schedule_enabled(db: AsyncSession, schedule: ScanSchedule, enabled: bool) -> ScanSchedule:
    schedule.enabled = enabled
    await db.flush()
    return schedule


async def delete_schedule(db: AsyncSession, schedule: ScanSchedule) -> None:
    await db.delete(schedule)
    await db.flush()


async def run_scheduled_scan(session_factory, schedule_id: str) -> None:
    """Llamado por el scheduler en proceso (APScheduler, ver app/main.py)
    cuando le toca disparar a una regla.

    Sin schedule.agent_id (comportamiento historico): crea un ScanJob nuevo
    -- igual que si un usuario lo hubiera lanzado a mano -- y lo ejecuta
    con el mismo codigo (execute_scan_job) que usa la creacion manual,
    esperando a que termine antes de anotar el resultado en last_status.

    Con schedule.agent_id: la corrida real la hace un agente remoto por
    polling (puede tardar, o el agente puede estar apagado), asi que aca
    NO se espera nada -- solo se crea el AgentScanJob (mismo mecanismo que
    create_agent_scan_job, ver "Escaneos remotos") y se anota que SE
    ENVIO. El resultado final queda en esa fila, visible en el panel de
    escaneos remotos, no en last_status de la regla."""
    async with session_factory() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if schedule is None or not schedule.enabled:
            return

        if schedule.agent_id:
            agent = await db.get(ScanAgent, schedule.agent_id)
            if agent is None or agent.organization_id != schedule.organization_id:
                schedule.last_run_at = _now()
                schedule.last_status = "error: el agente configurado ya no existe o no pertenece a esta organizacion"[:500]
                await db.commit()
                logger.error(
                    "escaneo programado con agente invalido",
                    extra={"schedule_id": schedule_id, "agent_id": schedule.agent_id},
                )
                return
            agent_job = AgentScanJob(
                organization_id=schedule.organization_id,
                agent_id=agent.id,
                name=f"{schedule.name or schedule.scanner_type.value} (programado)",
                scanner_type=schedule.scanner_type.value,
                target=schedule.target,
                options=schedule.options,
                created_by=f"scheduler:{schedule.name or schedule.id}",
            )
            db.add(agent_job)
            schedule.last_run_at = _now()
            schedule.last_status = f"enviado al agente {agent.name} -- resultado en Escaneos remotos"[:500]
            await db.flush()
            await db.commit()
            logger.info(
                "escaneo programado enviado a agente remoto",
                extra={"schedule_id": schedule_id, "agent_id": agent.id, "job_id": agent_job.id},
            )
            return

        job = ScanJob(
            organization_id=schedule.organization_id,
            name=f"{schedule.name or schedule.scanner_type.value} (programado)",
            scanner_type=schedule.scanner_type,
            target=schedule.target,
            options=schedule.options,
            created_by=f"scheduler:{schedule.name or schedule.id}",
        )
        db.add(job)
        schedule.last_run_at = _now()
        await db.flush()
        job_id = job.id
        await db.commit()

    try:
        await execute_scan_job(session_factory, job_id)
        status_note = "ok"
    except Exception as exc:  # noqa: BLE001 -- se registra en la propia regla, no se pierde silenciosamente
        logger.error("error corriendo escaneo programado", extra={"schedule_id": schedule_id, "error": str(exc)})
        status_note = f"error: {exc}"[:500]

    async with session_factory() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if schedule is not None:
            schedule.last_status = status_note
            await db.commit()


def driver_exception_error_message(exc: Exception) -> str:
    """Mensaje guardado en ScanJob.error_message cuando el driver levanta una
    excepcion no prevista (no capturada ya como ScanResult.error) -- funcion
    pura, separada de execute_scan_job, para poder testear el formato y el
    truncado a 2000 caracteres (limite de la columna, ver app/models.py)
    sin correr un scanner de verdad ni tocar la DB."""
    return f"Error inesperado del driver de escaneo: {exc}"[:2000]


async def execute_scan_job(session_factory, job_id: str) -> None:
    """Corre en background (via BackgroundTasks, o desde run_scheduled_scan
    para las reglas programadas). Usa su propia sesion de DB porque la
    request original ya termino cuando esto se ejecuta.

    Se auto-registra en _RUNNING_SCAN_TASKS mientras corre (via
    asyncio.current_task()) para que POST /scans/{id}/cancel pueda pedirle
    la cancelacion con Task.cancel() -- sea quien sea quien haya arrancado
    esta corrutina (BackgroundTasks de FastAPI o el scheduler de
    APScheduler), asyncio.current_task() devuelve la misma Task real que
    la esta ejecutando.

    Todo el cuerpo queda envuelto en un try/except CancelledError (no solo
    la llamada al driver): la cancelacion puede llegar en cualquier punto
    de espera, incluso antes de que el driver arranque a correr. Ese
    CancelledError se atrapa aca y NUNCA se re-lanza -- si escapara,
    run_scheduled_scan no lo atraparia con su `except Exception` (desde
    Python 3.8, CancelledError hereda de BaseException a proposito, para
    que nadie lo confunda con un error real del scanner), y quedaria como
    una excepcion sin manejar en el background task de FastAPI."""
    task = asyncio.current_task()
    if task is not None:
        register_running_scan(job_id, task)
    try:
        async with session_factory() as db:
            job = await db.get(ScanJob, job_id)
            if job is None:
                return
            if job.status == ScanStatus.cancelled:
                # Lo cancelaron (POST /scans/{id}/cancel -> cancel_scan_job)
                # ANTES de que esta tarea llegara a arrancar y registrarse en
                # _RUNNING_SCAN_TASKS -- sin este chequeo, lo de abajo pisa
                # el estado 'cancelled' con 'running' y despues 'completed',
                # como si la cancelacion nunca hubiera pasado (asi se veia
                # "el boton cancelar no funciona": cancelaba, pero el job
                # terminaba solo igual con resultados).
                return

            driver = get_driver(job.scanner_type)
            if not driver.is_available():
                job.status = ScanStatus.scanner_unavailable
                job.error_message = f"El binario '{driver.binary_name}' no esta disponible en este contenedor"
                job.finished_at = _now()
                await db.commit()
                logger.warning("scanner no disponible", extra={"job_id": job_id, "scanner": job.scanner_type.value})
                return

            job.status = ScanStatus.running
            job.started_at = _now()
            await db.commit()

            # driver.run() ya atrapa sus propios errores esperados (binario
            # ausente, timeout) y los devuelve como ScanResult.error -- pero un
            # driver puede levantar una excepcion no prevista (permiso denegado
            # al crear el subproceso, error de parseo no capturado, etc). Sin
            # este try/except, esa excepcion se escapa de este background task
            # (FastAPI solo la loguea, no hay nadie esperando la respuesta) y el
            # job se queda en estado "running" para siempre: nunca pasa a un
            # estado terminal, asi que ni se puede reintentar a mano ni se puede
            # borrar (is_deletable_status exige un estado terminal).
            try:
                result = await driver.run(job.target, job.options or {})
            except Exception as exc:  # noqa: BLE001 -- nunca debe dejar el job colgado en "running"
                job = await db.get(ScanJob, job_id)
                job.status = ScanStatus.failed
                job.error_message = driver_exception_error_message(exc)
                job.finished_at = _now()
                await db.commit()
                logger.error("scan fallo con excepcion no manejada", extra={"job_id": job_id, "error": str(exc)})
                return

            job = await db.get(ScanJob, job_id)
            job.raw_result = (result.raw_output or "")[:200_000]
            job.finished_at = _now()
            # OpenVasDriver.run() puede "marcar" el ScanResult con un
            # gvm_task_id extra (ver app/scanners/openvas.py::_tag) cuando
            # llega a crear un task real en gvmd, aunque el escaneo despues
            # falle o de timeout -- se guarda en options (no hay columna
            # propia) para que el dashboard de OpenVAS pueda pedir despues
            # el reporte completo/exportarlo (GET /openvas/tasks trae el
            # report_id de gvmd a partir de este task_id). Otros scanners
            # (nmap/trivy/nuclei) nunca settean este atributo, asi que esto
            # no les cambia nada.
            gvm_task_id = getattr(result, "gvm_task_id", None)
            if gvm_task_id:
                job.options = {**(job.options or {}), "gvm_task_id": gvm_task_id}
            if result.error:
                job.status = ScanStatus.failed
                job.error_message = result.error[:2000]
                logger.error("scan fallo", extra={"job_id": job_id, "error": result.error[:500]})
            else:
                job.status = ScanStatus.completed
                job.findings = result.findings
                # ScanResult (ver app/scanners/base.py) no declara ningun
                # campo "packages" -- NINGUN driver (nmap/trivy/nuclei/
                # openvas) lo setea hoy en el flujo generico de
                # execute_scan_job. El inventario de paquetes de trivy se
                # llena por una via COMPLETAMENTE distinta (la subida de un
                # archivo, ver execute_uploaded_scan_job mas arriba, que
                # escribe job.packages directo). Leer result.packages a
                # secas revienta con AttributeError en CUALQUIER escaneo
                # exitoso de este flujo -- dejando el job trabado en
                # 'running' para siempre, porque nunca se llega a este
                # commit. getattr(..., None) or [] lo deja en la misma
                # lista vacia que ya trae por default la columna (ver el
                # ALTER TABLE ... DEFAULT '[]' mas arriba en el lifespan).
                job.packages = getattr(result, "packages", None) or []
                logger.info("scan completado", extra={"job_id": job_id, "hallazgos": len(result.findings)})
            await db.commit()

            if result.findings:
                await _forward_findings_to_vuln_service(job)
                await _forward_findings_to_siem_service(job)
    except asyncio.CancelledError:
        # El usuario pidio cancelar (POST /scans/{id}/cancel -> cancel_scan_job
        # -> cancel_running_scan -> Task.cancel()). Los drivers ya atrapan este
        # mismo CancelledError junto al subproceso que tengan corriendo para
        # matarlo antes de volver a levantarlo (ver app/scanners/*.py) -- aca
        # solo queda dejar el job en un estado terminal. Se abre una sesion
        # NUEVA porque la sesion de arriba puede haber quedado en un estado
        # intermedio inconsistente si la cancelacion llego a mitad de un
        # commit/flush.
        async with session_factory() as db:
            job = await db.get(ScanJob, job_id)
            if job is not None and is_cancellable_status(job.status):
                job.status = ScanStatus.cancelled
                job.error_message = "Cancelado por el usuario"
                job.finished_at = _now()
                await db.commit()
        logger.info("scan cancelado", extra={"job_id": job_id})
    finally:
        unregister_running_scan(job_id)


async def _forward_findings_to_vuln_service(job: ScanJob) -> None:
    """Best-effort: si vuln-service no responde, el job de escaneo ya quedo
    guardado igual (los findings estan en ScanJob.findings); esto solo
    adelanta la ingesta para priorizacion automatica."""
    payload = {
        "scan_job_id": job.id,
        "asset_id": job.asset_id,
        "scanner_type": job.scanner_type.value,
        "findings": job.findings,
        "organization_id": job.organization_id,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{VULN_SERVICE_URL}/vulnerabilities/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar hallazgos a vuln-service", extra={"job_id": job.id, "error": str(exc)})


def _findings_to_siem_events(scanner_type: str, target: str, asset_id: str | None, findings: list[dict]) -> list[dict]:
    """Un evento ECS-lite por hallazgo, para que siem-service pueda
    evaluar reglas Sigma sobre resultados de escaneo (ver
    app/services.py::DEFAULT_RULES de siem-service, que ya trae reglas
    para severidad critica/alta de este mismo pipeline)."""
    return [
        {
            "host": target,
            "event_action": "scan_finding",
            "event_category": "vulnerability",
            "event_outcome": "success",
            "message": finding.get("title", ""),
            "source_type": scanner_type,
            "asset_id": asset_id,
            "severity": finding.get("severity", "info"),
        }
        for finding in findings
    ]


async def _forward_findings_to_siem_service(job: ScanJob) -> None:
    """Best-effort, igual que _forward_findings_to_vuln_service: si
    siem-service no responde, el job de escaneo ya quedo guardado igual."""
    payload = {
        "organization_id": job.organization_id,
        "events": _findings_to_siem_events(job.scanner_type.value, job.target, job.asset_id, job.findings),
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SIEM_SERVICE_URL}/logs/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar hallazgos a siem-service", extra={"job_id": job.id, "error": str(exc)})


# --- Agentes de escaneo remoto ---
# La key en si (no un hash lento tipo bcrypt) es la fuente de entropia:
# la genera el servidor con secrets.token_urlsafe, no la elige una persona,
# asi que sha256 alcanza y es barato para chequear en cada poll (que puede
# ocurrir cada pocos segundos por agente).

def _hash_agent_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def agent_key_matches(agent: ScanAgent, api_key: str) -> bool:
    """True si `api_key` en texto plano corresponde al agente dado (mismo
    hash guardado, ver _hash_agent_key). Se usa para exigir la api key del
    agente al LANZAR un escaneo remoto desde la UI, ademas del JWT del
    usuario: asi un escaneo remoto solo se puede crear si quien lo lanza
    conoce tambien la key del agente que lo va a ejecutar. Comparacion via
    el hash ya guardado -- la key en texto plano nunca se persiste."""
    return bool(api_key) and agent.key_hash == _hash_agent_key(api_key)


def is_protected_agent(agent) -> bool:
    """True si `agent` es uno de los bootstrap (Agente Docker/Agente LAN,
    ver ensure_bootstrap_agent) -- estos NO se pueden borrar desde la UI:
    si se borran, los escaneos remotos que dependen de ellos (los que
    arrancan solos con el stack, sin que nadie los registre a mano)
    dejan de poder lanzarse hasta el proximo reinicio de scan-service
    (que los vuelve a crear porque BOOTSTRAP_AGENTS sigue en .env), y
    mientras tanto cualquier job ya creado con esa api key queda huerfano."""
    value = agent.created_by if isinstance(agent.created_by, str) else str(agent.created_by)
    return value == "bootstrap"


def resolve_bootstrap_api_key(agent, bootstrap_agents_raw: str) -> str | None:
    """Si `agent` es uno de los definidos en BOOTSTRAP_AGENTS (el mismo
    JSON que main.py::lifespan usa para auto-crearlos), devuelve su api
    key en texto plano -- la UI la necesita para poder lanzar un escaneo
    remoto con el Agente Docker/Agente LAN (POST /agent-scans exige la
    key del agente ademas del JWT, ver agent_key_matches). El servidor
    NUNCA persiste esta key en texto plano (solo su hash, ver
    ScanAgent.key_hash) -- se recalcula al vuelo comparando hashes contra
    cada entrada de BOOTSTRAP_AGENTS. No es una fuga nueva: quien
    despliega el stack ya tiene esas keys en su propio .env."""
    if not is_protected_agent(agent) or not bootstrap_agents_raw.strip():
        return None
    try:
        entries = json.loads(bootstrap_agents_raw)
    except json.JSONDecodeError:
        return None
    for entry in entries or []:
        key = (entry or {}).get("key")
        if not key:
            continue
        if _hash_agent_key(key) == agent.key_hash:
            return key
    return None


async def ensure_bootstrap_agent(db: AsyncSession, name: str, api_key: str, organization_id: str) -> bool:
    """Crea (idempotente) un agente pre-provisionado desde configuracion
    (env BOOTSTRAP_AGENTS, ver main.py::lifespan). Sirve para que los
    agentes "siempre encendidos" -- el contenedor remote-agent y el agente
    de host de la LAN -- queden dados de alta solos al arrancar el stack,
    sin tener que registrarlos a mano desde la UI. Idempotente por key_hash:
    si ya existe un agente con esa misma key no hace nada, asi reiniciar el
    servicio no duplica agentes. Devuelve True si lo creo, False si ya
    estaba. La key la elige el operador (en .env), a diferencia de
    create_agent que la genera el servidor -- por eso aca no se devuelve la
    key en texto plano: ya la tiene quien configuro el .env."""
    key_hash = _hash_agent_key(api_key)
    existing = (await db.execute(select(ScanAgent).where(ScanAgent.key_hash == key_hash))).scalar_one_or_none()
    if existing is not None:
        # Si ya existe pero quedo en otro org (ej. se creo en DEFAULT antes de
        # saber el org real del usuario), lo movemos para que aparezca en su UI.
        if existing.organization_id != organization_id:
            existing.organization_id = organization_id
            existing.name = name
            await db.flush()
        return False
    db.add(ScanAgent(organization_id=organization_id, name=name, key_hash=key_hash, created_by="bootstrap"))
    await db.flush()
    return True


async def detect_primary_organization(db: AsyncSession, fallback: str) -> str:
    """Devuelve el organization_id 'real' de este deployment: el de los
    agentes o jobs que ya creo un usuario. Sirve para que los agentes
    bootstrap queden en el MISMO org que usa la cuenta (que puede NO ser
    DEFAULT segun como se registro) y asi aparezcan en su UI.

    BUG REAL que encontramos en produccion (Manu, 2026-09-29): las dos
    primeras anclas (un ScanAgent manual, o un AgentScanJob) son datos
    TRANSITORIOS que el usuario puede borrar por completo (ej. el boton
    "Limpiar todos los escaneos remotos" de la UI, o simplemente nunca
    haber registrado un agente manual) -- en cuanto no queda ninguna,
    esta funcion caia derecho al `fallback` (DEFAULT_ORGANIZATION_ID, un
    UUID FIJO interno de scan-service, ver backend/shared/tenancy.py),
    que casi nunca es el id REAL de la organizacion que auth-service le
    genero al usuario (ese es un UUID random). Resultado: en el
    siguiente reinicio, ensure_bootstrap_agent "movia" a Agente Docker/
    Agente LAN al organization_id equivocado y desaparecian de la UI del
    usuario sin ningun error visible.

    Por eso se agrega una tercera ancla, mucho mas estable: la tabla
    `organizations` (de auth-service, pero en la MISMA base fisica) --
    si hay una sola organizacion dada de alta, que es el caso tipico
    on-prem de un solo cliente, es sin duda la real. Con creds/schema
    invalidos (deployment sin esa tabla) esto no debe romper el arranque,
    de ahi el try/except."""
    q = await db.execute(
        select(ScanAgent.organization_id)
        .where(ScanAgent.created_by != "bootstrap", ScanAgent.organization_id.isnot(None))
        .order_by(ScanAgent.created_at.desc()).limit(1)
    )
    org = q.scalar_one_or_none()
    if org:
        return org
    q = await db.execute(
        select(AgentScanJob.organization_id)
        .where(AgentScanJob.organization_id.isnot(None))
        .order_by(AgentScanJob.created_at.desc()).limit(1)
    )
    org = q.scalar_one_or_none()
    if org:
        return org
    try:
        result = await db.execute(text("SELECT id FROM organizations LIMIT 2"))
        rows = result.fetchall()
        if len(rows) == 1:
            return str(rows[0][0])
    except Exception:  # noqa: BLE001 -- deployment sin tabla organizations, no debe tumbar el arranque
        pass
    return fallback


async def create_agent(db: AsyncSession, payload, actor: str, organization_id: str) -> tuple[ScanAgent, str]:
    api_key = secrets.token_urlsafe(32)
    agent = ScanAgent(
        organization_id=organization_id, name=payload.name, key_hash=_hash_agent_key(api_key), created_by=actor
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    return agent, api_key


async def list_agents(db: AsyncSession, organization_id: str) -> list[ScanAgent]:
    result = await db.execute(
        select(ScanAgent).where(ScanAgent.organization_id == organization_id).order_by(ScanAgent.created_at.desc())
    )
    return list(result.scalars().all())


async def get_agent(db: AsyncSession, agent_id: str, organization_id: str) -> ScanAgent | None:
    agent = await db.get(ScanAgent, agent_id)
    if agent is None or agent.organization_id != organization_id:
        return None
    return agent


async def get_agent_by_key(db: AsyncSession, api_key: str) -> ScanAgent | None:
    result = await db.execute(select(ScanAgent).where(ScanAgent.key_hash == _hash_agent_key(api_key)))
    return result.scalar_one_or_none()


async def delete_agent(db: AsyncSession, agent: ScanAgent) -> None:
    await db.delete(agent)
    await db.flush()


async def delete_agent_scan_job(db: AsyncSession, job: AgentScanJob) -> None:
    """Mismo criterio que delete_scan_job: solo estados terminales."""
    await db.delete(job)
    await db.flush()


async def create_agent_scan_job(db: AsyncSession, payload, actor: str, organization_id: str) -> AgentScanJob:
    job = AgentScanJob(
        organization_id=organization_id,
        agent_id=payload.agent_id,
        name=payload.name,
        scanner_type=payload.scanner_type,
        target=payload.target,
        options=payload.options,
        created_by=actor,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)
    return job


async def list_agent_scan_jobs(db: AsyncSession, organization_id: str, agent_id: str | None = None) -> list[AgentScanJob]:
    query = select(AgentScanJob).where(AgentScanJob.organization_id == organization_id)
    if agent_id:
        query = query.where(AgentScanJob.agent_id == agent_id)
    result = await db.execute(query.order_by(AgentScanJob.created_at.desc()))
    return list(result.scalars().all())


async def get_agent_scan_job(db: AsyncSession, job_id: str, organization_id: str) -> AgentScanJob | None:
    job = await db.get(AgentScanJob, job_id)
    if job is None or job.organization_id != organization_id:
        return None
    return job


# Cuanto espera un job "pending" mandado a un agente bootstrap especifico
# antes de volverse elegible para que el OTRO agente bootstrap se lo lleve
# (ver agent_can_claim_job). Mayor al POLL_INTERVAL_SECONDS por defecto del
# agente (10s, ver remote-agent/agent.py) para darle varias chances de
# pollear su propio job antes de que el otro compita por el.
UNIVERSAL_WORKER_GRACE_SECONDS = 60


def agent_can_claim_job(
    *,
    agent_id: str,
    is_bootstrap: bool,
    job_agent_id: str,
    job_status: str,
    job_created_at: datetime | None,
    job_assigned_at: datetime | None,
    now: datetime,
) -> bool:
    """Regla pura de si `agent_id` puede llevarse este job en su proximo
    poll (usada por poll_agent_jobs para filtrar los candidatos que ya trajo
    de la base). Antes, un agente bootstrap tomaba CUALQUIER job 'pending'
    apenas se creaba, sin importar a que agente lo habian mandado -- eso
    hacia que "Agente Docker" y "Agente LAN" compitieran por el mismo job
    recien creado (gana el que pollee primero, una moneda al aire): si
    Agente Docker ganaba un job pensado para un target de LAN, lo rechazaba
    al toque (ver AGENT_BEHIND_DOCKER_NAT en agent.py) ANTES de que Agente
    LAN -- online y capaz de resolverlo -- tuviera la chance de tomarlo el
    mismo, aunque el usuario lo hubiera elegido a proposito en el selector.

    Reglas:
    - El agente al que se lo mandaron explicitamente (job_agent_id) siempre
      puede tomarlo apenas esta 'pending', sin esperar nada.
    - Un agente bootstrap puede tomar un job 'pending' mandado a OTRO
      agente recien despues de UNIVERSAL_WORKER_GRACE_SECONDS -- le da
      tiempo al agente elegido de pollear su propio job primero si esta
      prendido; si no aparece en ese margen (ej. no corrio
      remote-agent/agente-lan.ps1), el otro bootstrap lo toma igual como
      red de contencion en vez de dejarlo pending para siempre.
    - Un agente bootstrap tambien recupera jobs 'assigned' huerfanos hace
      mas de 10 min (de un reinicio del agente antes de reportar el
      resultado) -- esto no cambio.
    - Un agente normal (no bootstrap) nunca entra por esta funcion: solo ve
      sus propios jobs pending via el query de poll_agent_jobs."""
    if job_status == "pending":
        if job_agent_id == agent_id:
            return True
        if not is_bootstrap:
            return False
        if job_created_at is None:
            return False
        return (now - job_created_at) >= timedelta(seconds=UNIVERSAL_WORKER_GRACE_SECONDS)
    if job_status == "assigned" and is_bootstrap:
        if job_assigned_at is None:
            return False
        return (now - job_assigned_at) >= timedelta(minutes=10)
    return False


async def poll_agent_jobs(db: AsyncSession, agent: ScanAgent, max_jobs: int = 5) -> list[AgentScanJob]:
    """Le entrega al agente sus jobs 'pending' y los pasa a 'assigned' en el
    mismo paso, para que un segundo poll (del mismo agente reiniciado, o de
    una instancia duplicada por error) no se lleve el mismo job dos veces."""
    agent.last_seen_at = _now()
    now = _now()
    is_bootstrap = agent.created_by == "bootstrap"
    if is_bootstrap:
        # Trae candidatos "pending" (de cualquier agente/org) y "assigned"
        # potencialmente huerfanos -- el filtro fino de cual puede tomar
        # cada uno (propio al toque, ajeno recien tras el margen de
        # gracia, huerfano tras 10 min) lo hace agent_can_claim_job abajo,
        # no el query, para poder testear esa regla sin DB real.
        stale_before = now - timedelta(minutes=10)
        query = select(AgentScanJob).where(
            or_(
                AgentScanJob.status == "pending",
                and_(
                    AgentScanJob.status == "assigned",
                    AgentScanJob.assigned_at.isnot(None),
                    AgentScanJob.assigned_at < stale_before,
                ),
            )
        )
    else:
        # Un agente normal solo ve SUS propios jobs pendientes.
        query = select(AgentScanJob).where(
            AgentScanJob.agent_id == agent.id, AgentScanJob.status == "pending"
        )
    result = await db.execute(query.order_by(AgentScanJob.created_at.asc()))
    candidates = list(result.scalars().all())
    if is_bootstrap:
        candidates = [
            job
            for job in candidates
            if agent_can_claim_job(
                agent_id=agent.id,
                is_bootstrap=True,
                job_agent_id=job.agent_id,
                job_status=job.status,
                job_created_at=job.created_at,
                job_assigned_at=job.assigned_at,
                now=now,
            )
        ]
    jobs = candidates[:max_jobs]
    for job in jobs:
        job.status = "assigned"
        job.assigned_at = _now()
    await db.flush()
    return jobs


SUBMITTABLE_AGENT_JOB_STATUSES = {"pending", "assigned"}


def is_submittable_status(status_value: str) -> bool:
    """Un agente solo puede reportar el resultado de un job que todavia no
    tiene un resultado final. Sin este chequeo, un doble submit (el agente
    reintentando tras perder la respuesta del primer POST, o dos procesos
    de agente corriendo por error con la misma api key) podia sobreescribir
    un resultado ya guardado (completed/failed) y volver a reenviar los
    mismos hallazgos a vuln-service/siem-service como si fueran nuevos."""
    return status_value in SUBMITTABLE_AGENT_JOB_STATUSES


async def get_agent_job_for_agent(db: AsyncSession, agent: ScanAgent, job_id: str) -> AgentScanJob | None:
    """Nunca se deja que un agente vea/escriba el resultado de un job que no
    es suyo -- ni por error de programacion del lado del agente, ni por una
    key comprometida usada para adivinar ids de otro agente."""
    job = await db.get(AgentScanJob, job_id)
    if job is None:
        return None
    # Un agente normal solo puede tocar sus propios jobs; un worker bootstrap
    # (ver poll_agent_jobs) puede reportar el de cualquiera, porque es el que
    # los ejecuta todos.
    if agent.created_by != "bootstrap" and job.agent_id != agent.id:
        return None
    return job


async def submit_agent_result(db: AsyncSession, agent: ScanAgent, job: AgentScanJob, payload) -> AgentScanJob:
    job.status = payload.status
    job.findings = payload.findings
    job.error_message = payload.error_message[:2000]
    job.finished_at = _now()
    agent.last_seen_at = _now()
    await db.flush()
    if payload.status == "completed" and payload.findings:
        await _forward_agent_findings_to_vuln_service(job)
        await _forward_agent_findings_to_siem_service(job)
    return job


async def _forward_agent_findings_to_vuln_service(job: AgentScanJob) -> None:
    """Mismo patron best-effort que _forward_findings_to_vuln_service: si
    vuln-service no responde, el job ya quedo guardado igual con sus
    findings. asset_id siempre None aca porque un agente remoto escanea
    targets de red (IP/CIDR), no un asset ya inventariado."""
    payload = {
        "scan_job_id": job.id,
        "asset_id": None,
        "scanner_type": job.scanner_type,
        "findings": job.findings,
        "organization_id": job.organization_id,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{VULN_SERVICE_URL}/vulnerabilities/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning(
            "no se pudo reenviar hallazgos de agente remoto a vuln-service",
            extra={"job_id": job.id, "error": str(exc)},
        )


async def _forward_agent_findings_to_siem_service(job: AgentScanJob) -> None:
    """Mismo patron best-effort, ver _forward_findings_to_siem_service."""
    payload = {
        "organization_id": job.organization_id,
        "events": _findings_to_siem_events(job.scanner_type, job.target, None, job.findings),
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SIEM_SERVICE_URL}/logs/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning(
            "no se pudo reenviar hallazgos de agente remoto a siem-service",
            extra={"job_id": job.id, "error": str(exc)},
        )
