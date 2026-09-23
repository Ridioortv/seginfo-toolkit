"""report-service entrypoint: reportes ejecutivos/de cumplimiento generados
100% a partir de datos ya existentes en otros servicios (nunca datos
inventados). Exportables como JSON, CSV o PDF; ver app/export.py. Tambien
soporta reportes programados que se generan solos y se mandan por email
como PDF adjunto via notification-service (ver app/services.py y el
scheduler en proceso mas abajo, mismo patron que scan-service)."""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.base import JobLookupError

from sqlalchemy import text
from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import (
    ReportRequest,
    GeneratedReportOut,
    ReportScheduleCreate,
    ReportScheduleUpdate,
    ReportScheduleOut,
)
from app.dependencies import get_current_claims, require_role
from app import services
from app.export import export_to_csv, export_to_pdf

logger = configure_logging("report-service")
reports_generated_total = Counter("report_generated_total", "Reportes generados", ["report_type"])

# Scheduler en proceso para las reglas de reporte recurrente
# (ReportSchedule) -- mismo patron simple ya usado en scan-service, sin
# infraestructura de colas externa. timezone explicito a proposito, y en
# los DOS lugares que lo piden (el scheduler Y cada CronTrigger, mas
# abajo): sin esto, APScheduler intenta autodetectar la zona horaria del
# sistema (tzlocal) y en una imagen Debian "slim" como la de este
# contenedor eso puede fallar duro al arrancar (o al crear cualquier
# regla) si el sistema reporta una zona para la que no tiene datos de
# zoneinfo instalados -- tumbando todo el servicio. Default UTC;
# configurable con SCHEDULER_TIMEZONE si se quiere que las horas de las
# reglas (hour/minute) se interpreten en otra zona.
_SCHEDULER_TZ = os.getenv("SCHEDULER_TIMEZONE", "UTC")
scheduler = AsyncIOScheduler(timezone=_SCHEDULER_TZ)


def _job_id(schedule_id: str) -> str:
    return f"report-schedule:{schedule_id}"


def _cron_trigger_for(schedule) -> CronTrigger:
    if schedule.frequency == "weekly":
        return CronTrigger(
            day_of_week=schedule.day_of_week, hour=schedule.hour, minute=schedule.minute, timezone=_SCHEDULER_TZ
        )
    return CronTrigger(hour=schedule.hour, minute=schedule.minute, timezone=_SCHEDULER_TZ)


def _register_job(schedule) -> None:
    scheduler.add_job(
        services.run_scheduled_report,
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
        await conn.execute(text("ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text("ALTER TABLE generated_reports ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text(
            f"UPDATE report_schedules SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text(
            f"UPDATE generated_reports SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    async with SessionLocal() as db:
        for schedule in await services.list_schedules(db):
            if schedule.enabled:
                _register_job(schedule)
    scheduler.start()
    logger.info("report-service iniciado", extra={"reportes_programados": len(scheduler.get_jobs())})
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SentinelOps Report Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "report-service"}


@app.post("/reports/generate", response_model=GeneratedReportOut, status_code=status.HTTP_201_CREATED)
async def generate_report(
    payload: ReportRequest,
    request: Request,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    auth_header = request.headers.get("authorization")
    report = await services.generate_report(
        db, payload.report_type, auth_header, claims.get("sub", ""), org_id_from_claims(claims)
    )
    await db.commit()
    reports_generated_total.labels(report_type=payload.report_type).inc()
    return report


@app.get("/reports", response_model=list[GeneratedReportOut])
async def list_reports(
    report_type: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_reports(db, org_id_from_claims(claims), report_type)


@app.get("/reports/{report_id}", response_model=GeneratedReportOut)
async def get_report(report_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    report = await services.get_report(db, report_id, org_id_from_claims(claims))
    if report is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    return report


@app.get("/reports/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = "json",
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    report = await services.get_report(db, report_id, org_id_from_claims(claims))
    if report is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    if format == "csv":
        csv_text = export_to_csv(report.report_type, report.data)
        return Response(content=csv_text, media_type="text/csv")
    if format == "pdf":
        pdf_bytes = export_to_pdf(report.report_type, report.data)
        filename = f"reporte_{report.report_type}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return GeneratedReportOut.model_validate(report).model_dump(mode="json")


@app.post("/report-schedules", response_model=ReportScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ReportScheduleCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.create_schedule(db, payload, claims.get("sub", ""), org_id_from_claims(claims))
    await db.commit()
    _register_job(schedule)
    logger.info("regla de reporte programado creada", extra={"schedule_id": schedule.id})
    return schedule


@app.get("/report-schedules", response_model=list[ReportScheduleOut])
async def list_schedules_endpoint(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_schedules(db, org_id_from_claims(claims))


@app.patch("/report-schedules/{schedule_id}", response_model=ReportScheduleOut)
async def update_schedule(
    schedule_id: str,
    payload: ReportScheduleUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.get_schedule(db, schedule_id, org_id_from_claims(claims))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Regla de reporte no encontrada")
    schedule = await services.set_schedule_enabled(db, schedule, payload.enabled)
    await db.commit()
    if payload.enabled:
        _register_job(schedule)
    else:
        _unregister_job(schedule_id)
    return schedule


@app.delete("/report-schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.get_schedule(db, schedule_id, org_id_from_claims(claims))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Regla de reporte no encontrada")
    await services.delete_schedule(db, schedule)
    await db.commit()
    _unregister_job(schedule_id)
