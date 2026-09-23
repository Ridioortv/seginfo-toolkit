"""scan-service entrypoint: orquestacion de escaneres defensivos
(nmap/trivy/nuclei/openvas) en modo SOLO DETECCION. Ver
app/scanners/base.py y docs/architecture.md para el alcance."""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.base import JobLookupError

from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from app.schemas import ScanJobCreate, ScanJobOut, ScanScheduleCreate, ScanScheduleUpdate, ScanScheduleOut
from app.dependencies import get_current_claims, require_role
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
    async with SessionLocal() as db:
        for schedule in await services.list_schedules(db):
            if schedule.enabled:
                _register_job(schedule)
    scheduler.start()
    logger.info("scan-service iniciado", extra={"reglas_programadas": len(scheduler.get_jobs())})
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SentinelOps Scan Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
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
    job = await services.create_scan_job(db, payload, claims.get("sub", ""))
    await db.commit()
    scan_jobs_total.labels(scanner_type=payload.scanner_type.value).inc()
    logger.info("scan job creado", extra={"job_id": job.id, "scanner": payload.scanner_type.value})
    background_tasks.add_task(services.execute_scan_job, SessionLocal, job.id)
    return job


@app.get("/scans", response_model=list[ScanJobOut])
async def list_scans(
    status_filter: str | None = None,
    scanner_type: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_scan_jobs(db, status_filter, scanner_type)


@app.get("/scans/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    job = await services.get_scan_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    return job


@app.post("/scan-schedules", response_model=ScanScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScanScheduleCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.create_schedule(db, payload, claims.get("sub", ""))
    await db.commit()
    _register_job(schedule)
    logger.info("regla de escaneo programado creada", extra={"schedule_id": schedule.id})
    return schedule


@app.get("/scan-schedules", response_model=list[ScanScheduleOut])
async def list_schedules_endpoint(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_schedules(db)


@app.patch("/scan-schedules/{schedule_id}", response_model=ScanScheduleOut)
async def update_schedule(
    schedule_id: str,
    payload: ScanScheduleUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.get_schedule(db, schedule_id)
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
    schedule = await services.get_schedule(db, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Regla de escaneo no encontrada")
    await services.delete_schedule(db, schedule)
    await db.commit()
    _unregister_job(schedule_id)
