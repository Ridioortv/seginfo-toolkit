"""Business logic for scan-service: orquestacion de jobs de escaneo
DEFENSIVOS (solo deteccion) y reenvio de hallazgos normalizados a
vuln-service para priorizacion (CVSS/EPSS/KEV)."""
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import ScanJob, ScanStatus, ScannerType, ScanSchedule
from app.scanners import get_driver, DRIVERS

logger = configure_logging("scan-service")

VULN_SERVICE_URL = os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_scan_job(db: AsyncSession, payload, actor: str) -> ScanJob:
    job = ScanJob(
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
    db: AsyncSession, status_filter: str | None = None, scanner_type: str | None = None
) -> list[ScanJob]:
    query = select(ScanJob)
    if status_filter:
        query = query.where(ScanJob.status == status_filter)
    if scanner_type:
        query = query.where(ScanJob.scanner_type == scanner_type)
    result = await db.execute(query.order_by(ScanJob.created_at.desc()))
    return list(result.scalars().all())


async def get_scan_job(db: AsyncSession, job_id: str) -> ScanJob | None:
    return await db.get(ScanJob, job_id)


def scanners_status() -> dict:
    return {scanner_type.value: driver.is_available() for scanner_type, driver in DRIVERS.items()}


async def create_schedule(db: AsyncSession, payload, actor: str) -> ScanSchedule:
    schedule = ScanSchedule(
        name=payload.name,
        scanner_type=payload.scanner_type,
        target=payload.target,
        options=payload.options,
        frequency=payload.frequency,
        hour=payload.hour,
        minute=payload.minute,
        day_of_week=payload.day_of_week,
        created_by=actor,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


async def list_schedules(db: AsyncSession) -> list[ScanSchedule]:
    result = await db.execute(select(ScanSchedule).order_by(ScanSchedule.created_at.desc()))
    return list(result.scalars().all())


async def get_schedule(db: AsyncSession, schedule_id: str) -> ScanSchedule | None:
    return await db.get(ScanSchedule, schedule_id)


async def set_schedule_enabled(db: AsyncSession, schedule: ScanSchedule, enabled: bool) -> ScanSchedule:
    schedule.enabled = enabled
    await db.flush()
    return schedule


async def delete_schedule(db: AsyncSession, schedule: ScanSchedule) -> None:
    await db.delete(schedule)
    await db.flush()


async def run_scheduled_scan(session_factory, schedule_id: str) -> None:
    """Llamado por el scheduler en proceso (APScheduler, ver app/main.py)
    cuando le toca disparar a una regla. Crea un ScanJob nuevo -- igual que
    si un usuario lo hubiera lanzado a mano -- y lo ejecuta con el mismo
    codigo (execute_scan_job) que usa la creacion manual."""
    async with session_factory() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if schedule is None or not schedule.enabled:
            return
        job = ScanJob(
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


async def execute_scan_job(session_factory, job_id: str) -> None:
    """Corre en background (via BackgroundTasks). Usa su propia sesion de DB
    porque la request original ya termino cuando esto se ejecuta."""
    async with session_factory() as db:
        job = await db.get(ScanJob, job_id)
        if job is None:
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

        result = await driver.run(job.target, job.options or {})

        job = await db.get(ScanJob, job_id)
        job.raw_result = (result.raw_output or "")[:200_000]
        job.finished_at = _now()
        if result.error:
            job.status = ScanStatus.failed
            job.error_message = result.error[:2000]
            logger.error("scan fallo", extra={"job_id": job_id, "error": result.error[:500]})
        else:
            job.status = ScanStatus.completed
            job.findings = result.findings
            logger.info("scan completado", extra={"job_id": job_id, "hallazgos": len(result.findings)})
        await db.commit()

        if result.findings:
            await _forward_findings_to_vuln_service(job)


async def _forward_findings_to_vuln_service(job: ScanJob) -> None:
    """Best-effort: si vuln-service no responde, el job de escaneo ya quedo
    guardado igual (los findings estan en ScanJob.findings); esto solo
    adelanta la ingesta para priorizacion automatica."""
    payload = {
        "scan_job_id": job.id,
        "asset_id": job.asset_id,
        "scanner_type": job.scanner_type.value,
        "findings": job.findings,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{VULN_SERVICE_URL}/vulnerabilities/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar hallazgos a vuln-service", extra={"job_id": job.id, "error": str(exc)})
