"""Tests de I/O de coderepo-service con SQLite en memoria y git/gitleaks/trivy
falseados: estado "running" visible, errores que quedan guardados y avisos
cuando una herramienta no pudo correr (antes: "ok, 0 hallazgos" falso)."""
import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import services
from app.models import Base, RepoScanStatus, RepoTarget


def _run(coro_fn):
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


async def _new_target(factory):
    async with factory() as db:
        t = RepoTarget(name="r", repo_url="https://github.com/o/r", branch="main", organization_id="o1")
        db.add(t)
        await db.commit()
        return t.id


class TestRunning:
    def test_mark_started_then_is_running(self):
        async def body(factory):
            tid = await _new_target(factory)
            async with factory() as db:
                t = await db.get(RepoTarget, tid)
                assert not services.is_scan_running(t)
                await services.mark_scan_started(db, t)
                await db.commit()
                return services.is_scan_running(t), t.last_scan_status

        running, status = _run(body)
        assert running and status == RepoScanStatus.running

    def test_stale_running_is_not_running(self):
        t = RepoTarget(name="r", repo_url="u", last_scan_status=RepoScanStatus.running,
                       last_scan_at=datetime.now(timezone.utc) - timedelta(hours=2))
        assert services.is_scan_running(t) is False

    def test_running_value_fits_the_widened_column_name(self):
        assert RepoScanStatus.running.value == "running"


class TestRunRepoScanNow:
    def test_unexpected_exception_is_recorded_as_error(self, monkeypatch):
        async def boom(*a, **k):
            raise RuntimeError("se rompio")

        monkeypatch.setattr(services, "run_repo_scan", boom)

        async def body(factory):
            tid = await _new_target(factory)
            async with factory() as db:
                await services.mark_scan_started(db, await db.get(RepoTarget, tid))
                await db.commit()
            await services.run_repo_scan_now(factory, tid)
            async with factory() as db:
                return await db.get(RepoTarget, tid)

        t = _run(body)
        assert t.last_scan_status == RepoScanStatus.error and "se rompio" in t.last_scan_error

    def test_missing_tools_finish_ok_but_leave_a_warning(self, monkeypatch):
        async def fake_clone(*a, **k):
            return None

        async def no_binary(*a, **k):
            raise FileNotFoundError("nope")

        monkeypatch.setattr(services, "_clone_repo", fake_clone)
        monkeypatch.setattr(services.asyncio, "create_subprocess_exec", no_binary)

        async def body(factory):
            tid = await _new_target(factory)
            await services.run_repo_scan_now(factory, tid)
            async with factory() as db:
                return await db.get(RepoTarget, tid)

        t = _run(body)
        assert t.last_scan_status == RepoScanStatus.ok
        assert t.last_scan_error.startswith("Aviso:")
        assert "gitleaks no esta instalado" in t.last_scan_error and "trivy no esta instalado" in t.last_scan_error

    def test_clean_run_has_no_warning(self, monkeypatch):
        async def fake_clone(*a, **k):
            return None

        async def fake_gitleaks(path, warnings=None):
            return []

        async def fake_trivy(path, name, warnings=None):
            return []

        monkeypatch.setattr(services, "_clone_repo", fake_clone)
        monkeypatch.setattr(services, "_run_gitleaks", fake_gitleaks)
        monkeypatch.setattr(services, "_run_trivy_fs", fake_trivy)

        async def body(factory):
            tid = await _new_target(factory)
            await services.run_repo_scan_now(factory, tid)
            async with factory() as db:
                return await db.get(RepoTarget, tid)

        t = _run(body)
        assert t.last_scan_status == RepoScanStatus.ok and t.last_scan_error == ""
