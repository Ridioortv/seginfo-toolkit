"""Lo abierto hoy (para Cumplimiento): por severidad, explotadas activamente (KEV) y la critica mas vieja."""
import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import services
from app.models import Base, VulnSeverity, VulnStatus, Vulnerability


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


def test_posture_counts_only_open_ones_of_the_org():
    now = datetime.now(timezone.utc)

    async def body(factory):
        async with factory() as db:
            def add(i, sev, status=VulnStatus.open, kev=False, days=1, org="o1"):
                db.add(Vulnerability(organization_id=org, title=f"v{i}", severity=sev, status=status, is_kev=kev,
                                     source_scanner="x", created_at=now - timedelta(days=days)))
            add(1, VulnSeverity.critical, days=40)
            add(2, VulnSeverity.critical, status=VulnStatus.confirmed, days=3, kev=True)
            add(3, VulnSeverity.high)
            add(4, VulnSeverity.critical, status=VulnStatus.remediated, days=90)   # no cuenta
            add(5, VulnSeverity.critical, status=VulnStatus.false_positive)        # no cuenta
            add(6, VulnSeverity.critical, org="o2", days=500)                      # otra organizacion
            await db.commit()
            return await services.get_posture(db, "o1"), await services.get_posture(db, "vacia")

    p, empty = run(body)
    assert p["open_total"] == 3 and p["open_by_severity"] == {"critical": 2, "high": 1}
    assert p["open_kev"] == 1 and 39.9 <= p["oldest_open_days"]["critical"] <= 40.1 and p["oldest_open_days"]["high"] < 2
    assert empty == {"open_total": 0, "open_by_severity": {}, "open_kev": 0, "oldest_open_days": {"critical": 0.0, "high": 0.0}}
