"""scan-service entrypoint: orquestacion de escaneres defensivos
(nmap/trivy/nuclei/openvas) en modo SOLO DETECCION. Ver
app/scanners/base.py y docs/architecture.md para el alcance."""
import os
import asyncio
from contextlib import asynccontextmanager
import tempfile
import httpx
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.base import JobLookupError

from sqlalchemy import text
from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import (
    ScanJobCreate,
    ScanJobOut,
    ScanScheduleCreate,
    ScanScheduleUpdate,
    ScanScheduleOut,
    ScanAgentCreate,
    ScanAgentOut,
    ScanAgentCreated,
    AgentScanJobCreate,
    AgentScanJobOut,
    AgentPollResponse,
    AgentPollJob,
    AgentResultSubmit,
    ImageInventoryItem,
    OpenvasActivateRequest,
    OpenvasStatusOut,
    OpenvasAutoActivateRequest,
    OpenvasProgressOut,
    GvmEntityOut,
    GvmCredentialCreate,
    GvmCredentialOut,
    GvmTargetCreate,
    GvmTargetOut,
    GvmTaskOut,
)
from app.dependencies import get_current_claims, require_role, get_agent_from_key
from app.scanners.openvas import probe_connection as _probe_openvas_connection
from app import gvm_manage
from app import services

logger = configure_logging("scan-service")
scan_jobs_total = Counter("scan_jobs_total", "Jobs de escaneo creados", ["scanner_type"])

# Scheduler en proceso para las reglas de escaneo recurrente (ScanSchedule).
# Una sola instancia de scan-service = un solo scheduler -- no hace falta
# infraestructura de colas para esto, y es el mismo patron simple que ya
# usa el resto de la plataforma (sin brokers externos).
# timezone explicito a proposito, y en los DOS lugares que lo piden
# (el scheduler Y cada CronTrigger, mas abajo): sin esto, APScheduler
# intenta autodetectar la zona horaria del sistema (tzlocal) y en una
# imagen Debian "slim" como la de este contenedor eso puede fallar duro
# al arrancar (o al crear cualquier regla) si el sistema reporta una
# zona para la que no tiene datos de zoneinfo instalados -- tumbando
# todo el servicio. Default UTC; configurable con SCHEDULER_TIMEZONE si
# se quiere que las horas de las reglas (hour/minute) se interpreten en
# otra zona.
_SCHEDULER_TZ = os.getenv("SCHEDULER_TIMEZONE", "UTC")
scheduler = AsyncIOScheduler(timezone=_SCHEDULER_TZ)


def _job_id(schedule_id: str) -> str:
    return f"scan-schedule:{schedule_id}"


def _cron_trigger_for(schedule) -> CronTrigger:
    if schedule.frequency == "weekly":
        return CronTrigger(
            day_of_week=schedule.day_of_week, hour=schedule.hour, minute=schedule.minute, timezone=_SCHEDULER_TZ
        )
    return CronTrigger(hour=schedule.hour, minute=schedule.minute, timezone=_SCHEDULER_TZ)


def _register_job(schedule) -> None:
    scheduler.add_job(
        services.run_scheduled_scan,
        trigger=_cron_trigger_for(schedule),
        args=[SessionLocal, schedule.id],
        id=_job_id(schedule.id),
        replace_existing=True,
        misfire_grace_time=3600,
    )


def _unregister_job(schedule_id: str) -> None:
    try:
        scheduler.remove_job(_job_id(schedule_id))
    except JobLookupError:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for table in ("scan_schedules", "scan_jobs", "scan_agents", "agent_scan_jobs"):
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
            await conn.execute(text(
                f"UPDATE {table} SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
            ))
        # Inventario de paquetes de trivy (ver ScanJob.packages en models.py):
        # columna nueva, instalaciones existentes la necesitan via ALTER TABLE
        # (create_all solo crea TABLAS que faltan, no columnas nuevas en una
        # tabla que ya existe).
        await conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS packages JSON DEFAULT '[]'"))
        await conn.execute(text("UPDATE scan_jobs SET packages = '[]' WHERE packages IS NULL"))
        # ScanSchedule.agent_id (ver models.py): columna nueva, mismo motivo
        # que las de arriba. NULL es un valor valido (regla sin agente, el
        # comportamiento historico) asi que no hace falta ningun UPDATE de
        # backfill -- a diferencia de organization_id/packages, que no
        # podian quedar NULL.
        await conn.execute(text("ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS agent_id VARCHAR(36)"))
    async with SessionLocal() as db:
        for schedule in await services.list_schedules(db):
            if schedule.enabled:
                _register_job(schedule)

    # Auto-provision de agentes de escaneo remoto "siempre encendidos" (ver
    # BOOTSTRAP_AGENTS en .env): se dan de alta solos al arrancar, sin
    # registro manual desde la UI. Idempotente. Nunca debe tumbar el
    # arranque, aunque el JSON venga mal formado.
    # TODO el bloque va envuelto: el auto-registro NUNCA debe impedir que
    # arranque scan-service. Cualquier error aca (JSON malo, DB, etc.) solo
    # se loguea y el servicio arranca igual.
    try:
        import json as _json
        _raw_bootstrap = os.getenv("BOOTSTRAP_AGENTS", "").strip()
        if _raw_bootstrap:
            _entries = _json.loads(_raw_bootstrap)
            async with SessionLocal() as db:
                _org = await services.detect_primary_organization(db, DEFAULT_ORGANIZATION_ID)
                for _entry in _entries or []:
                    _name = (_entry or {}).get("name")
                    _key = (_entry or {}).get("key")
                    if not _name or not _key:
                        continue
                    if await services.ensure_bootstrap_agent(db, _name, _key, _org):
                        logger.info("agente bootstrap creado", extra={"agent_name": _name, "org": _org})
                await db.commit()
                logger.info("agentes bootstrap en org", extra={"org": _org})
    except Exception as _exc:  # noqa: BLE001 -- el auto-registro nunca tumba el arranque
        logger.warning("no se pudieron provisionar agentes bootstrap", extra={"error": str(_exc)})
    # Refresh periodico de datos de escaner (DB de CVEs de trivy, plantillas
    # de nuclei) en segundo plano -- asi cada escaneo individual no paga el
    # costo de descarga/actualizacion (ver app/scanners/trivy.py y
    # app/scanners/nuclei.py, que corren con --skip-db-update / -duc).
    # next_run_time=ahora para que corra una vez apenas arranca el servicio
    # (por si el volumen persistente esta vacio en el primer `docker compose up`)
    # y despues cada N horas.
    from datetime import datetime as _dt
    scheduler.add_job(
        services.refresh_trivy_db,
        trigger=IntervalTrigger(hours=24),
        id="trivy-db-refresh",
        replace_existing=True,
        next_run_time=_dt.now(),
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        services.refresh_nuclei_templates,
        trigger=IntervalTrigger(hours=12),
        id="nuclei-templates-refresh",
        replace_existing=True,
        next_run_time=_dt.now(),
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info("scan-service iniciado", extra={"reglas_programadas": len(scheduler.get_jobs())})
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SentinelOps Scan Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "scan-service"}


@app.get("/scanners/status")
async def scanners_status(claims: dict = Depends(get_current_claims)):
    return services.scanners_status()


_DEFAULT_GVM_SOCKET_PATH = "/run/gvmd/gvmd.sock"
# openvas-orchestrator: el UNICO servicio con acceso al socket de Docker
# (ver openvas-orchestrator/main.py y docker-compose.yml) -- lo que hace
# posible /openvas/auto-activate* mas abajo. Mismo patron que
# VULN_SERVICE_URL/SIEM_SERVICE_URL en services.py.
OPENVAS_ORCHESTRATOR_URL = os.getenv("OPENVAS_ORCHESTRATOR_URL", "http://openvas-orchestrator:8000")


async def _call_orchestrator(method: str, path: str, *, json_body: dict | None = None, timeout: float = 15) -> dict:
    """POST/GET al orquestador con un puñado de reintentos cortos antes de
    darse por vencido. Docker (sobre todo Docker Desktop en Windows/WSL2)
    puede tardar un instante en resolver por DNS interno el nombre de un
    contenedor recien creado o reiniciado ("Name or service not known")
    aunque el contenedor este sano -- un solo intento fallido no significa
    que el orquestador este caido de verdad. Los reintentos son todos
    contra el MISMO host (OPENVAS_ORCHESTRATOR_URL); recien si los 3
    fallan se levanta el 502 real."""
    last_exc: httpx.HTTPError | None = None
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.request(method, f"{OPENVAS_ORCHESTRATOR_URL}{path}", json=json_body)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            last_exc = exc
            if attempt < 2:
                await asyncio.sleep(1.5)
    raise HTTPException(status_code=502, detail=f"No se pudo contactar al orquestador de OpenVAS: {last_exc}")


@app.get("/openvas/status", response_model=OpenvasStatusOut)
async def openvas_status(claims: dict = Depends(get_current_claims)):
    """A diferencia de /scanners/status (que solo mira si gvm-cli esta
    instalado), esto prueba la conexion GMP real con las credenciales
    actuales -- lo que necesita el boton "Activar OpenVAS" del frontend
    para saber si ya se sumo (o se cayo) como scanner remoto disponible."""
    user = os.getenv("GVM_USER") or ""
    password = os.getenv("GVM_PASSWORD") or ""
    if not user or not password:
        return OpenvasStatusOut(
            configured=False,
            ready=False,
            detail="Todavia no se configuraron credenciales GVM_USER/GVM_PASSWORD.",
        )
    socket_path = os.getenv("GVM_SOCKET_PATH") or _DEFAULT_GVM_SOCKET_PATH
    ok, detail = await _probe_openvas_connection(socket_path, user, password, timeout=15)
    return OpenvasStatusOut(configured=True, ready=ok, detail=detail)


@app.post("/openvas/activate", response_model=OpenvasStatusOut)
async def openvas_activate(
    payload: OpenvasActivateRequest,
    claims: dict = Depends(require_role("admin", "soc_manager")),
):
    """Aplica credenciales GVM en memoria para este proceso, sin reiniciar
    el contenedor -- este servicio no tiene acceso al socket de Docker, asi
    que NO puede levantar los contenedores de GVM el mismo (eso lo sigue
    haciendo openvas/Encender-OpenVAS.ps1 a mano, ver LEEME.md). Lo que si
    hace es probar la conexion GMP real ANTES de aplicar nada: si gvmd
    todavia no esta arriba o las credenciales son invalidas, devuelve 422
    con el detalle en vez de "activar" algo que en realidad no funciona.

    Esta activacion dura hasta el proximo reinicio de scan-service -- para
    que quede tambien despues de un reinicio hay que correr
    Configurar-OpenVAS.ps1 (que ademas de esto mismo escribe las
    credenciales en .env)."""
    socket_path = payload.gvm_socket_path.strip() or os.getenv("GVM_SOCKET_PATH") or _DEFAULT_GVM_SOCKET_PATH
    ok, detail = await _probe_openvas_connection(socket_path, payload.gvm_user, payload.gvm_password, timeout=20)
    if not ok:
        raise HTTPException(status_code=422, detail=detail)
    os.environ["GVM_USER"] = payload.gvm_user
    os.environ["GVM_PASSWORD"] = payload.gvm_password
    os.environ["GVM_SOCKET_PATH"] = socket_path
    logger.info("openvas activado desde la UI (credenciales aplicadas en memoria, sin reiniciar el contenedor)")
    return OpenvasStatusOut(configured=True, ready=True, detail=detail)


@app.post("/openvas/auto-activate", response_model=OpenvasProgressOut)
async def openvas_auto_activate(
    payload: OpenvasAutoActivateRequest,
    claims: dict = Depends(require_role("admin", "soc_manager")),
):
    """A diferencia de /openvas/activate (que solo prueba credenciales
    contra un gvmd que YA esta arriba, levantado a mano con
    openvas/Encender-OpenVAS.ps1), esto le pide a openvas-orchestrator --
    el unico servicio con acceso al socket de Docker, ver
    openvas-orchestrator/main.py -- que levante el profile "openvas" el
    mismo (~16 contenedores), cree/actualice el usuario GVM, y guarde las
    credenciales en .env. Puede tardar 20-40 minutos la primera vez
    (sincronizacion de feeds) asi que esto solo DISPARA el proceso y
    devuelve al toque -- el frontend consulta el progreso con
    GET /openvas/auto-activate/progress."""
    socket_path = payload.gvm_socket_path.strip() or os.getenv("GVM_SOCKET_PATH") or _DEFAULT_GVM_SOCKET_PATH
    data = await _call_orchestrator(
        "POST", "/start",
        json_body={"gvm_user": payload.gvm_user, "gvm_password": payload.gvm_password, "gvm_socket_path": socket_path},
    )
    logger.info("activacion automatica de openvas disparada", extra={"actor": claims.get("sub")})
    return OpenvasProgressOut(**data, ready=False)


@app.get("/openvas/auto-activate/progress", response_model=OpenvasProgressOut)
async def openvas_auto_activate_progress(claims: dict = Depends(require_role("admin", "soc_manager"))):
    """Progreso de la activacion automatica disparada por
    POST /openvas/auto-activate. Cuando el orquestador ya termino de
    levantar los contenedores y crear el usuario GVM (`provisioned`), esto
    ADEMAS prueba la conexion GMP de verdad -- misma funcion que usa
    /openvas/activate -- antes de aplicar las credenciales en memoria y
    recien ahi devolver `ready=True`; nunca se confia ciegamente en lo que
    reporta el orquestador."""
    data = await _call_orchestrator("GET", "/status", timeout=10)

    ready = False
    probe_error = None
    if data.get("provisioned") and data.get("gvm_user") and data.get("gvm_password"):
        socket_path = data.get("gvm_socket_path") or os.getenv("GVM_SOCKET_PATH") or _DEFAULT_GVM_SOCKET_PATH
        ok, detail = await _probe_openvas_connection(socket_path, data["gvm_user"], data["gvm_password"], timeout=15)
        if ok:
            os.environ["GVM_USER"] = data["gvm_user"]
            os.environ["GVM_PASSWORD"] = data["gvm_password"]
            os.environ["GVM_SOCKET_PATH"] = socket_path
            ready = True
        else:
            probe_error = detail

    return OpenvasProgressOut(
        running=data.get("running", False),
        provisioned=data.get("provisioned", False),
        ready=ready,
        phase=data.get("phase", ""),
        percent=data.get("percent", 0),
        detail=data.get("detail", ""),
        error=data.get("error") or probe_error,
        gvm_user=data.get("gvm_user"),
        gvm_password=data.get("gvm_password"),
    )


# --- Dashboard de OpenVAS ---------------------------------------------------
# Una vez activo (ver /openvas/status), esto deja elegir tipo de escaneo,
# credenciales para escaneo autenticado y targets reusables -- en vez de que
# OpenVasDriver.run() elija todo solo (ver app/scanners/openvas.py) -- y ver/
# exportar el reporte completo de gvmd de un analisis ya terminado. Todo pasa
# por app/gvm_manage.py, que habla GMP directo con gvmd (misma via que ya usa
# el driver, gvm-cli sobre el socket).

def _require_gvm_credentials() -> tuple[str, str, str]:
    """Mismas GVM_USER/GVM_PASSWORD/GVM_SOCKET_PATH que ya aplica en memoria
    /openvas/activate o /openvas/auto-activate/progress -- si todavia no se
    activo OpenVAS desde la UI, ninguna de las operaciones del dashboard
    tiene con quien hablar."""
    user = os.getenv("GVM_USER") or ""
    password = os.getenv("GVM_PASSWORD") or ""
    if not user or not password:
        raise HTTPException(
            status_code=409,
            detail="OpenVAS todavia no esta activado -- primero arrancalo desde 'Activar OpenVAS' en Escaneos.",
        )
    socket_path = os.getenv("GVM_SOCKET_PATH") or _DEFAULT_GVM_SOCKET_PATH
    return socket_path, user, password


@app.get("/openvas/configs", response_model=list[GvmEntityOut])
async def list_openvas_configs(claims: dict = Depends(get_current_claims)):
    socket_path, user, password = _require_gvm_credentials()
    ok, configs, err = await gvm_manage.list_configs(socket_path, user, password)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudieron listar los tipos de escaneo: {err}")
    return configs


@app.get("/openvas/port-lists", response_model=list[GvmEntityOut])
async def list_openvas_port_lists(claims: dict = Depends(get_current_claims)):
    socket_path, user, password = _require_gvm_credentials()
    ok, port_lists, err = await gvm_manage.list_port_lists(socket_path, user, password)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudieron listar las listas de puertos: {err}")
    return port_lists


@app.get("/openvas/report-formats", response_model=list[GvmEntityOut])
async def list_openvas_report_formats(claims: dict = Depends(get_current_claims)):
    socket_path, user, password = _require_gvm_credentials()
    ok, formats, err = await gvm_manage.list_report_formats(socket_path, user, password)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudieron listar los formatos de reporte: {err}")
    return formats


@app.get("/openvas/credentials", response_model=list[GvmCredentialOut])
async def list_openvas_credentials(claims: dict = Depends(get_current_claims)):
    socket_path, user, password = _require_gvm_credentials()
    ok, creds, err = await gvm_manage.list_credentials(socket_path, user, password)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudieron listar las credenciales: {err}")
    return [
        GvmCredentialOut(id=c["id"], name=c["name"], login=c.get("login", ""), credential_type=c.get("type", ""))
        for c in creds
    ]


@app.post("/openvas/credentials", response_model=GvmCredentialOut, status_code=status.HTTP_201_CREATED)
async def create_openvas_credential(
    payload: GvmCredentialCreate,
    # Mismos roles que create/delete de targets y que POST /scans
    # (require_role("admin", "soc_manager", "analyst")) -- antes esto
    # solo aceptaba admin/soc_manager, una inconsistencia sin motivo
    # aparente que hacia que un analyst pudiera crear targets/lanzar
    # escaneos pero se topara con un 403 silencioso (mostrado como "no se
    # pudo crear la credencial" en el dashboard) justo al crear
    # credenciales de escaneo autenticado.
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
):
    socket_path, user, password = _require_gvm_credentials()
    ok, credential_id, err = await gvm_manage.create_credential(
        socket_path, user, password, payload.name, payload.login, payload.password,
    )
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudo crear la credencial: {err}")
    logger.info("credencial GVM creada", extra={"actor": claims.get("sub"), "credential_id": credential_id})
    return GvmCredentialOut(id=credential_id, name=payload.name, login=payload.login, credential_type="up")


@app.delete("/openvas/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_openvas_credential(
    credential_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
):
    socket_path, user, password = _require_gvm_credentials()
    ok, err = await gvm_manage.delete_credential(socket_path, user, password, credential_id)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudo borrar la credencial: {err}")
    logger.info("credencial GVM borrada", extra={"actor": claims.get("sub"), "credential_id": credential_id})


@app.get("/openvas/targets", response_model=list[GvmTargetOut])
async def list_openvas_targets(claims: dict = Depends(get_current_claims)):
    socket_path, user, password = _require_gvm_credentials()
    ok, targets, err = await gvm_manage.list_targets(socket_path, user, password)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudieron listar los targets: {err}")
    return targets


@app.post("/openvas/targets", response_model=GvmTargetOut, status_code=status.HTTP_201_CREATED)
async def create_openvas_target(
    payload: GvmTargetCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
):
    socket_path, user, password = _require_gvm_credentials()
    ok, target_id, err = await gvm_manage.create_target(
        socket_path, user, password, payload.name, payload.hosts, payload.port_list_id,
        payload.ssh_credential_id, payload.smb_credential_id,
    )
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudo crear el target: {err}")
    logger.info("target GVM creado", extra={"actor": claims.get("sub"), "target_id": target_id})
    return GvmTargetOut(
        id=target_id, name=payload.name, hosts=payload.hosts, port_list_id=payload.port_list_id,
        ssh_credential_id=payload.ssh_credential_id, smb_credential_id=payload.smb_credential_id,
    )


@app.delete("/openvas/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_openvas_target(
    target_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
):
    socket_path, user, password = _require_gvm_credentials()
    ok, err = await gvm_manage.delete_target(socket_path, user, password, target_id)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudo borrar el target: {err}")
    logger.info("target GVM borrado", extra={"actor": claims.get("sub"), "target_id": target_id})


@app.get("/openvas/tasks", response_model=list[GvmTaskOut])
async def list_openvas_tasks(claims: dict = Depends(get_current_claims)):
    socket_path, user, password = _require_gvm_credentials()
    ok, tasks, err = await gvm_manage.list_tasks(socket_path, user, password)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudieron listar los analisis: {err}")
    return tasks


@app.get("/openvas/reports/{report_id}")
async def get_openvas_report(report_id: str, claims: dict = Depends(get_current_claims)):
    """Reporte NATIVO completo de gvmd (todos los hosts/resultados/metadata
    de la corrida) -- para "ver el reporte completo" en el dashboard, a
    diferencia de los findings ya resumidos que guarda cada ScanJob."""
    socket_path, user, password = _require_gvm_credentials()
    ok, raw_xml, err = await gvm_manage.get_report_xml(socket_path, user, password, report_id)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudo obtener el reporte: {err}")
    return {"report_id": report_id, "raw_xml": raw_xml}


@app.get("/openvas/reports/{report_id}/export")
async def export_openvas_report(
    report_id: str,
    format: str = "pdf",
    claims: dict = Depends(get_current_claims),
):
    socket_path, user, password = _require_gvm_credentials()
    ok, content, filename, err = await gvm_manage.export_report(socket_path, user, password, report_id, format)
    if not ok:
        raise HTTPException(status_code=502, detail=f"no se pudo exportar el reporte: {err}")
    media_types = {"pdf": "application/pdf", "xml": "application/xml", "csv": "text/csv"}
    media_type = media_types.get(format.strip().lower(), "application/octet-stream")
    logger.info(
        "reporte OpenVAS exportado", extra={"actor": claims.get("sub"), "report_id": report_id, "format": format},
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/scans", response_model=ScanJobOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanJobCreate,
    background_tasks: BackgroundTasks,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.create_scan_job(db, payload, claims.get("sub", ""), org_id_from_claims(claims))
    await db.commit()
    scan_jobs_total.labels(scanner_type=payload.scanner_type.value).inc()
    logger.info("scan job creado", extra={"job_id": job.id, "scanner": payload.scanner_type.value})
    background_tasks.add_task(services.execute_scan_job, SessionLocal, job.id)
    return job


_MAX_UPLOAD_BYTES = 600 * 1024 * 1024  # 600 MB


@app.post("/scans/upload", response_model=ScanJobOut, status_code=status.HTTP_201_CREATED)
async def upload_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    name: str = Form(""),
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Sube un archivo (imagen .tar exportada con `docker save`, o un
    manifiesto de paquetes: requirements.txt, package-lock.json, etc.) y lo
    escanea con trivy. El resultado queda como un escaneo normal.

    Solo GUARDA el archivo y crea el job aca -- la corrida de trivy (que
    puede tardar varios minutos con una imagen grande) se dispara en
    background, igual que POST /scans para escaneos por target, en vez de
    correr dentro de este mismo request/response. Antes, con un archivo
    grande, el request quedaba abierto hasta que trivy terminara y
    cualquier corte de conexion de por medio se veia como un confuso
    'Network Error' sin relacion con la causa real."""
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="El archivo supera el limite de 600 MB")
    safe_name = os.path.basename(file.filename or "archivo")
    display_name = name or safe_name
    tmpdir = tempfile.mkdtemp(prefix="trivy-upload-")
    dest = os.path.join(tmpdir, safe_name)
    with open(dest, "wb") as fh:
        fh.write(content)
    job = await services.create_uploaded_scan_job(db, display_name, claims.get("sub", ""), org_id_from_claims(claims))
    await db.commit()
    scan_jobs_total.labels(scanner_type="trivy").inc()
    logger.info("scan de archivo subido creado", extra={"job_id": job.id, "archivo": display_name})
    background_tasks.add_task(services.execute_uploaded_scan_job, SessionLocal, job.id, dest, tmpdir)
    return job


@app.get("/scans", response_model=list[ScanJobOut])
async def list_scans(
    status_filter: str | None = None,
    scanner_type: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_scan_jobs(db, org_id_from_claims(claims), status_filter, scanner_type)


@app.get("/scans/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    job = await services.get_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    return job


@app.delete("/scans/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    job_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    if services.is_running_status(job.status):
        raise HTTPException(status_code=409, detail="No se puede borrar un escaneo en curso; cancelalo primero")
    await services.delete_scan_job(db, job)
    await db.commit()
    logger.info("scan job borrado", extra={"job_id": job_id, "actor": claims.get("sub")})


@app.post("/scans/{job_id}/cancel", response_model=ScanJobOut)
async def cancel_scan(
    job_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    if not services.is_cancellable_status(job.status):
        raise HTTPException(status_code=409, detail="Solo se pueden cancelar escaneos pendientes o en curso")
    job = await services.cancel_scan_job(db, job)
    await db.commit()
    logger.info("scan job cancelado", extra={"job_id": job_id, "actor": claims.get("sub")})
    return job


@app.get("/scan-images", response_model=list[ImageInventoryItem])
async def list_image_inventory(
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Dashboard: una fila por imagen/archivo escaneado con trivy (el mas
    reciente si se reescaneo mas de una vez), con su inventario COMPLETO de
    paquetes -- no solo los que tienen CVE (eso ya esta en 'Escaneos
    realizados' via `findings`). Ver services.get_image_inventory."""
    return await services.get_image_inventory(db, org_id_from_claims(claims))


@app.post("/scan-schedules", response_model=ScanScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScanScheduleCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    organization_id = org_id_from_claims(claims)
    # Mismo chequeo que create_agent_scan (ver mas abajo): si la regla va a
    # correr via un agente remoto, se exige la api key de ESE agente ademas
    # del JWT del usuario, para confirmar que quien crea la regla lo conoce
    # -- nunca se persiste (ver ScanScheduleCreate.agent_api_key).
    if payload.agent_id:
        agent = await services.get_agent(db, payload.agent_id, organization_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="Agente no encontrado")
        if not services.agent_key_matches(agent, payload.agent_api_key or ""):
            raise HTTPException(status_code=401, detail="La api key no corresponde al agente elegido")
    schedule = await services.create_schedule(db, payload, claims.get("sub", ""), organization_id)
    await db.commit()
    _register_job(schedule)
    logger.info(
        "regla de escaneo programado creada",
        extra={"schedule_id": schedule.id, "agent_id": schedule.agent_id},
    )
    return schedule


@app.get("/scan-schedules", response_model=list[ScanScheduleOut])
async def list_schedules_endpoint(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_schedules(db, org_id_from_claims(claims))


@app.patch("/scan-schedules/{schedule_id}", response_model=ScanScheduleOut)
async def update_schedule(
    schedule_id: str,
    payload: ScanScheduleUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.get_schedule(db, schedule_id, org_id_from_claims(claims))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Regla de escaneo no encontrada")
    schedule = await services.set_schedule_enabled(db, schedule, payload.enabled)
    await db.commit()
    if payload.enabled:
        _register_job(schedule)
    else:
        _unregister_job(schedule_id)
    return schedule


@app.delete("/scan-schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.get_schedule(db, schedule_id, org_id_from_claims(claims))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Regla de escaneo no encontrada")
    await services.delete_schedule(db, schedule)
    await db.commit()
    _unregister_job(schedule_id)


# --- Agentes de escaneo remoto ---
# El agente (remote-agent/agent.py) corre FUERA de Docker (en la misma PC
# o en cualquier maquina de la LAN) y hace polling hacia este puerto ya
# publicado (8003) -- nunca al reves, asi que no hace falta abrir ningun
# puerto de entrada en la red del cliente. Ver app/models.py::ScanAgent.

@app.post("/agents", response_model=ScanAgentCreated, status_code=status.HTTP_201_CREATED)
async def create_agent(
    payload: ScanAgentCreate,
    claims: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    agent, api_key = await services.create_agent(db, payload, claims.get("sub", ""), org_id_from_claims(claims))
    await db.commit()
    logger.info("agente de escaneo remoto creado", extra={"agent_id": agent.id})
    # api_key solo existe en texto plano en esta respuesta -- el servidor
    # ya solo tiene su hash guardado (ver ScanAgent.key_hash).
    return ScanAgentCreated(
        id=agent.id, name=agent.name, created_by=agent.created_by,
        created_at=agent.created_at, last_seen_at=agent.last_seen_at, api_key=api_key,
    )


@app.get("/agents", response_model=list[ScanAgentOut])
async def list_agents(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    agents = await services.list_agents(db, org_id_from_claims(claims))
    bootstrap_raw = os.getenv("BOOTSTRAP_AGENTS", "")
    return [
        ScanAgentOut(
            id=a.id,
            name=a.name,
            created_by=a.created_by,
            created_at=a.created_at,
            last_seen_at=a.last_seen_at,
            is_protected=services.is_protected_agent(a),
            bootstrap_api_key=services.resolve_bootstrap_api_key(a, bootstrap_raw),
        )
        for a in agents
    ]


@app.delete("/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: str,
    claims: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    agent = await services.get_agent(db, agent_id, org_id_from_claims(claims))
    if agent is None:
        raise HTTPException(status_code=404, detail="Agente no encontrado")
    if services.is_protected_agent(agent):
        raise HTTPException(
            status_code=409,
            detail=(
                "Este agente se crea solo al arrancar el stack (BOOTSTRAP_AGENTS en .env) y no se puede "
                "borrar desde aca -- si lo borras, los escaneos remotos que dependen de el dejan de "
                "funcionar hasta el proximo reinicio de scan-service."
            ),
        )
    await services.delete_agent(db, agent)
    await db.commit()


@app.post("/agent-scans", response_model=AgentScanJobOut, status_code=status.HTTP_201_CREATED)
async def create_agent_scan(
    payload: AgentScanJobCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    organization_id = org_id_from_claims(claims)
    agent = await services.get_agent(db, payload.agent_id, organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agente no encontrado")
    # Se exige la api key del agente elegido ademas del JWT: lanzar un
    # escaneo remoto requiere conocer la key del agente que lo ejecutara.
    if not services.agent_key_matches(agent, payload.api_key):
        raise HTTPException(status_code=401, detail="La api key no corresponde al agente elegido")
    job = await services.create_agent_scan_job(db, payload, claims.get("sub", ""), organization_id)
    await db.commit()
    logger.info("job de escaneo remoto creado", extra={"job_id": job.id, "agent_id": payload.agent_id})
    return job


@app.get("/agent-scans", response_model=list[AgentScanJobOut])
async def list_agent_scans(
    agent_id: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_agent_scan_jobs(db, org_id_from_claims(claims), agent_id)


@app.delete("/agent-scans/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent_scan(
    job_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_agent_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo remoto no encontrado")
    await services.delete_agent_scan_job(db, job)
    await db.commit()
    logger.info("scan job remoto borrado", extra={"job_id": job_id, "actor": claims.get("sub")})


@app.post("/agents/poll", response_model=AgentPollResponse)
async def poll_agent(agent=Depends(get_agent_from_key), db: AsyncSession = Depends(get_db)):
    jobs = await services.poll_agent_jobs(db, agent)
    await db.commit()
    return AgentPollResponse(
        jobs=[
            AgentPollJob(id=j.id, scanner_type=j.scanner_type, target=j.target, options=j.options)
            for j in jobs
        ]
    )


@app.post("/agents/results/{job_id}", response_model=AgentScanJobOut)
async def submit_agent_result(
    job_id: str,
    payload: AgentResultSubmit,
    agent=Depends(get_agent_from_key),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_agent_job_for_agent(db, agent, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job no encontrado o no pertenece a este agente")
    if not services.is_submittable_status(job.status):
        raise HTTPException(
            status_code=409,
            detail="Este job de escaneo remoto ya tiene un resultado final, no se puede sobreescribir",
        )
    job = await services.submit_agent_result(db, agent, job, payload)
    await db.commit()
    logger.info("resultado de escaneo remoto recibido", extra={"job_id": job_id, "status": payload.status})
    return job
