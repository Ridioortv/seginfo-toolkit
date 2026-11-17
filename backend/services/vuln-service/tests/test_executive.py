"""Numeros del tablero ejecutivo: abiertas hoy, flujo del periodo contra el anterior y exposicion por activo."""
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


def test_executive_period_vs_previous_and_exposure():
    now = datetime(2026, 6, 30, tzinfo=timezone.utc)

    async def body(factory):
        async with factory() as db:
            def add(i, sev, status=VulnStatus.open, kev=False, created=1, fixed=None, asset="a1", org="o1"):
                db.add(Vulnerability(organization_id=org, title=f"v{i}", severity=sev, status=status, is_kev=kev,
                                     source_scanner="x", asset_id=asset, created_at=now - timedelta(days=created),
                                     remediated_at=(now - timedelta(days=fixed)) if fixed is not None else None))
            add(1, VulnSeverity.critical, created=45, kev=True)            # abierta, vieja, KEV
            add(2, VulnSeverity.high, created=5)                          # abierta, nueva
            add(3, VulnSeverity.medium, created=70, asset="a2")           # abierta
            add(4, VulnSeverity.critical, status=VulnStatus.remediated, created=20, fixed=3)   # cerrada en el periodo
            add(5, VulnSeverity.high, status=VulnStatus.remediated, created=80, fixed=40)      # cerrada en el periodo anterior
            add(6, VulnSeverity.low, status=VulnStatus.accepted_risk, created=10)
            add(7, VulnSeverity.critical, org="o2", created=2)             # otra organizacion
            await db.commit()
            return await services.get_executive(db, "o1", 30, now), await services.get_executive(db, "vacia", 3, now)

    r, empty = run(body)
    assert r["days"] == 30
    assert r["open"]["total"] == 3 and r["open"]["by_severity"] == {"critical": 1, "high": 1, "medium": 1}
    assert r["open"]["kev"] == 1 and r["open"]["critical_high"] == 2 and r["open"]["oldest_critical_high_days"] == 45
    assert r["open"]["accepted_risk"] == 1
    assert r["period"]["created"] == 3 and r["period"]["remediated"] == 1 and r["period"]["remediated_critical_high"] == 1
    assert r["previous"]["created"] == 1 and r["previous"]["remediated"] == 1
    top = r["by_asset"]
    assert top[0]["asset_id"] == "a1" and top[0]["score"] == 10 * 1.5 + 5 and top[0]["kev"] == 1
    assert top[1]["asset_id"] == "a2" and top[1]["score"] == 2
    assert empty["days"] == 7 and empty["open"]["total"] == 0 and empty["by_asset"] == []
