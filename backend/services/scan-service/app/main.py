"""scan-service entrypoint: orquestacion de escaneres defensivos
(trivy/nuclei) en modo SOLO DETECCION. Ver
app/scanners/base.py y docs/architecture.md para el alcance."""
import os
import asyncio
import shutil
from contextlib import asynccontextmanager
import tempfile
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
)
from app.dependencies import get_current_claims, require_role, get_agent_from_key
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
        # scanner_type/status son SAEnum(native_enum=False): SQLAlchemy crea la
        # columna como VARCHAR(largo del nombre mas largo del enum EN ESE
        # MOMENTO). En instalaciones creadas cuando el enum solo tenia
        # trivy/nuclei, quedo VARCHAR(6) y guardar 'gitleaks' (8) o
        # 'semgrep' (7) revienta con un 500 -- que el navegador ve como
        # "Network Error" (la respuesta 500 no lleva cabeceras CORS).
        # create_all no altera columnas existentes, asi que se ensanchan
        # aca (idempotente: ampliar a VARCHAR(30) nunca pierde datos).
        for table, column in (
            ("scan_schedules", "scanner_type"),
            ("scan_jobs", "scanner_type"),
            ("scan_jobs", "status"),
        ):
            await conn.execute(text(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE VARCHAR(30)"))
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


_YARA_MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB en total, sumando todos los archivos
_YARA_MAX_FILES = 50


@app.post("/scans/upload-yara", response_model=ScanJobOut, status_code=status.HTTP_201_CREATED)
async def upload_yara_scan(
    background_tasks: BackgroundTasks,
    files: list[UploadFile] = File(...),
    name: str = Form(""),
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Sube uno o varios archivos y los analiza con YARA (reglas propias de
    SentinelOps) dentro de scan-service. Los archivos se guardan en una
    carpeta temporal, SOLO se leen como bytes (YARA nunca ejecuta lo que
    analiza), y la carpeta se borra al terminar el analisis, pase lo que
    pase. Mismo patron que POST /scans/upload (trivy): crea el job y
    devuelve al toque, el analisis corre en background."""
    if not files:
        raise HTTPException(status_code=400, detail="Subi al menos un archivo")
    if len(files) > _YARA_MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Maximo {_YARA_MAX_FILES} archivos por analisis")

    tmpdir = tempfile.mkdtemp(prefix="yara-upload-")
    saved: list[str] = []
    try:
        total = 0
        for index, upload in enumerate(files, start=1):
            # basename: un nombre tipo "../../etc/x" nunca puede escapar de tmpdir.
            safe_name = os.path.basename((upload.filename or "").replace("\\", "/")) or f"archivo-{index}"
            dest = os.path.join(tmpdir, safe_name)
            if os.path.exists(dest):
                dest = os.path.join(tmpdir, f"{index}-{safe_name}")
            with open(dest, "wb") as fh:
                while chunk := await upload.read(1024 * 1024):
                    total += len(chunk)
                    if total > _YARA_MAX_UPLOAD_BYTES:
                        raise HTTPException(status_code=413, detail="Los archivos superan el limite de 200 MB en total")
                    fh.write(chunk)
            saved.append(os.path.basename(dest))
    except BaseException:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    display_name = name.strip() or (saved[0] if len(saved) == 1 else f"{len(saved)} archivos ({', '.join(saved)})")
    target_path = os.path.join(tmpdir, saved[0]) if len(saved) == 1 else tmpdir
    try:
        job = await services.create_uploaded_yara_job(db, display_name, claims.get("sub", ""), org_id_from_claims(claims))
        await db.commit()
    except BaseException:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    scan_jobs_total.labels(scanner_type="yara").inc()
    logger.info("scan yara de archivos subidos creado", extra={"job_id": job.id, "archivos": len(saved)})
    background_tasks.add_task(services.execute_scan_job, SessionLocal, job.id, target_path, tmpdir)
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
