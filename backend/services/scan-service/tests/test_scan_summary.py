"""Resumen liviano de escaneos para Cumplimiento: terminados en la ventana, ultimo terminado y programados."""
import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import services
from app.models import Base, ScanJob, ScanSchedule, ScanStatus, ScannerType


def run(coro_fn):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async def main():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            return await coro_fn(factory)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def test_scan_summary():
    now = datetime.now(timezone.utc)

    async def body(factory):
        async with factory() as db:
            def job(status, days_ago, org="o1"):
                db.add(ScanJob(organization_id=org, name="n", scanner_type=ScannerType.nuclei, target="http://x.com",
                               status=status, finished_at=now - timedelta(days=days_ago)))
            job(ScanStatus.completed, 2)
            job(ScanStatus.completed, 10)
            job(ScanStatus.completed, 60)       # fuera de la ventana de 30 dias
            job(ScanStatus.failed, 1)           # no cuenta: no termino bien
            job(ScanStatus.completed, 1, "o2")  # otra organizacion
            for enabled in (True, False):
                db.add(ScanSchedule(organization_id="o1", name="s", scanner_type=ScannerType.nuclei, target="http://x.com",
                                    frequency="daily", hour=3, minute=0, enabled=enabled, created_by="a"))
            await db.commit()
            return await services.scan_summary(db, "o1"), await services.scan_summary(db, "nadie")

    s, empty = run(body)
    assert s["completed_in_window"] == 2 and s["schedules_total"] == 2 and s["schedules_enabled"] == 1
    assert s["last_completed_at"] and s["window_days"] == 30
    assert empty == {"window_days": 30, "completed_in_window": 0, "last_completed_at": None, "schedules_total": 0, "schedules_enabled": 0}
