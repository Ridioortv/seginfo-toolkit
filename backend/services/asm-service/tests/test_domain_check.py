"""Tests de I/O de asm-service con SQLite en memoria y la red falseada:
"Chequear ahora" (estado visible, TLS en paralelo, crt.sh con reintento) y
"Borrar" (borra tambien subdominios/alertas/certificados del dominio)."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import services
from app.models import Base, DiscoveredAsset, MonitoredDomain, SslCertificate, SurfaceAlert


def _run(engine, coro_fn):
    async def main():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            return await coro_fn(factory)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def _fresh_engine():
    return create_async_engine("sqlite+aiosqlite:///:memory:")


FUTURE = datetime.now(timezone.utc) + timedelta(days=200)


def _cert_ok(**kw):
    return {"issuer": "CN=Test CA", "subject": "CN=x", "not_before": datetime.now(timezone.utc),
            "not_after": FUTURE, "fingerprint_sha256": "ab" * 32, **kw}


class TestAsyncioRegression:
    """Bug: services.py no importaba asyncio a nivel de modulo, asi que
    _resolve_hostname_ips tiraba NameError y TODO chequeo TLS fallaba."""

    def test_resolve_hostname_ips_does_not_raise_nameerror(self):
        ips = asyncio.run(services._resolve_hostname_ips("localhost", 443))
        assert any(ip in ("127.0.0.1", "::1") for ip in ips)

    def test_fetch_tls_certificate_reports_blocked_ip_not_nameerror(self):
        result = asyncio.run(services.fetch_tls_certificate("localhost", timeout=3))
        assert "error" in result and "NameError" not in result["error"]
        assert "bloqueada" in result["error"]


class TestCrtshRetry:
    def _client(self, handler):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    def test_retries_once_after_503(self, monkeypatch):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(503, text="busy")
            return httpx.Response(200, json=[{"name_value": "www.example.com"}, {"name_value": "api.example.com"}])

        async def fast_sleep(_):
            return None

        monkeypatch.setattr(services.asyncio, "sleep", fast_sleep)

        async def go():
            async with self._client(handler) as c:
                return await services.fetch_crtsh_detailed("example.com", c)

        subs, err = asyncio.run(go())
        assert err is None and {"www.example.com", "api.example.com"} <= subs and calls["n"] == 2

    def test_reports_error_when_always_failing(self, monkeypatch):
        async def fast_sleep(_):
            return None

        monkeypatch.setattr(services.asyncio, "sleep", fast_sleep)

        async def go():
            async with self._client(lambda r: httpx.Response(502, text="bad")) as c:
                return await services.fetch_crtsh_detailed("example.com", c)

        subs, err = asyncio.run(go())
        assert subs == set() and err and "502" in err


class TestSummarizeCheck:
    def test_ok(self):
        status, detail = services.summarize_check(
            {"subdomains": 3, "new_subdomains": 2, "certs_checked": 3, "cert_errors": 0, "crtsh_error": None})
        assert status == "ok" and "3 hostname" in detail

    def test_partial_when_crtsh_failed(self):
        status, detail = services.summarize_check(
            {"subdomains": 1, "new_subdomains": 1, "certs_checked": 1, "cert_errors": 1, "crtsh_error": "HTTPStatusError: 503"})
        assert status == "partial" and "crt.sh no respondio" in detail and "error de conexion TLS" in detail


class TestRunDomainCheckNow:
    def test_success_records_ok_status_assets_and_certs(self, monkeypatch):
        async def fake_crt(domain, client, attempts=2):
            return {"www.example.com", "api.example.com"}, None

        async def fake_tls(hostname, port=443, timeout=10.0):
            return _cert_ok()

        monkeypatch.setattr(services, "fetch_crtsh_detailed", fake_crt)
        monkeypatch.setattr(services, "fetch_tls_certificate", fake_tls)

        async def body(factory):
            async with factory() as db:
                d = await services.create_domain(db, "example.com", "org1", "u")
                await services.mark_check_started(db, d)
                await db.commit()
                dom_id = d.id
                assert services.is_check_running(d)
            await services.run_domain_check_now(factory, dom_id)
            async with factory() as db:
                d = await db.get(MonitoredDomain, dom_id)
                assets = (await db.execute(select(DiscoveredAsset))).scalars().all()
                certs = (await db.execute(select(SslCertificate))).scalars().all()
                alerts = (await db.execute(select(SurfaceAlert))).scalars().all()
                return d, assets, certs, alerts

        d, assets, certs, alerts = _run(_fresh_engine(), body)
        assert d.last_check_status == "ok" and "3 hostname" in d.last_check_detail
        assert sorted(a.hostname for a in assets) == ["api.example.com", "example.com", "www.example.com"]
        assert len(certs) == 3
        assert len([a for a in alerts if a.alert_type.value == "new_subdomain"]) == 3

    def test_crtsh_failure_is_partial_and_still_checks_root(self, monkeypatch):
        async def fake_crt(domain, client, attempts=2):
            return set(), "ReadTimeout: x"

        async def fake_tls(hostname, port=443, timeout=10.0):
            return {"error": "TimeoutError: x"}

        monkeypatch.setattr(services, "fetch_crtsh_detailed", fake_crt)
        monkeypatch.setattr(services, "fetch_tls_certificate", fake_tls)

        async def body(factory):
            async with factory() as db:
                d = await services.create_domain(db, "example.com", "org1", "u")
                await db.commit()
                dom_id = d.id
            await services.run_domain_check_now(factory, dom_id)
            async with factory() as db:
                return await db.get(MonitoredDomain, dom_id)

        d = _run(_fresh_engine(), body)
        assert d.last_check_status == "partial" and "crt.sh no respondio" in d.last_check_detail

    def test_unexpected_exception_records_error_status(self, monkeypatch):
        async def boom(*a, **k):
            raise RuntimeError("se rompio")

        monkeypatch.setattr(services, "run_domain_check", boom)

        async def body(factory):
            async with factory() as db:
                d = await services.create_domain(db, "example.com", "org1", "u")
                await services.mark_check_started(db, d)
                await db.commit()
                dom_id = d.id
            await services.run_domain_check_now(factory, dom_id)
            async with factory() as db:
                return await db.get(MonitoredDomain, dom_id)

        d = _run(_fresh_engine(), body)
        assert d.last_check_status == "error" and "se rompio" in d.last_check_detail

    def test_tls_checks_run_concurrently(self, monkeypatch):
        state = {"now": 0, "max": 0}

        async def fake_crt(domain, client, attempts=2):
            return {f"h{i}.example.com" for i in range(8)}, None

        async def slow_tls(hostname, port=443, timeout=10.0):
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
            await asyncio.sleep(0.05)
            state["now"] -= 1
            return _cert_ok()

        monkeypatch.setattr(services, "fetch_crtsh_detailed", fake_crt)
        monkeypatch.setattr(services, "fetch_tls_certificate", slow_tls)

        async def body(factory):
            async with factory() as db:
                d = await services.create_domain(db, "example.com", "org1", "u")
                await db.commit()
                dom_id = d.id
            await services.run_domain_check_now(factory, dom_id)

        _run(_fresh_engine(), body)
        assert state["max"] > 1


class TestIsCheckRunning:
    def test_stale_running_is_not_running(self):
        d = MonitoredDomain(domain="x.com", last_check_status="running",
                            last_checked_at=datetime.now(timezone.utc) - timedelta(hours=1))
        assert services.is_check_running(d) is False

    def test_fresh_running_is_running_and_idle_is_not(self):
        fresh = MonitoredDomain(domain="x.com", last_check_status="running", last_checked_at=datetime.now(timezone.utc))
        idle = MonitoredDomain(domain="x.com", last_check_status="ok", last_checked_at=datetime.now(timezone.utc))
        assert services.is_check_running(fresh) is True and services.is_check_running(idle) is False


class TestDeleteDomain:
    def test_cascades_assets_alerts_and_orphan_certs_but_keeps_other_domains(self):
        async def body(factory):
            async with factory() as db:
                a = await services.create_domain(db, "a.com", "org1", "u")
                b = await services.create_domain(db, "b.com", "org1", "u")
                for dom, host in ((a, "a.com"), (a, "shared.com"), (b, "shared.com"), (b, "b.com")):
                    db.add(DiscoveredAsset(organization_id="org1", monitored_domain_id=dom.id, hostname=host))
                    db.add(SurfaceAlert(organization_id="org1", monitored_domain_id=dom.id, hostname=host, detail="x"))
                for host in ("a.com", "shared.com", "b.com"):
                    db.add(SslCertificate(organization_id="org1", hostname=host))
                await db.commit()
                await services.delete_domain(db, a)
                await db.commit()
                domains = [d.domain for d in (await db.execute(select(MonitoredDomain))).scalars().all()]
                assets = sorted((x.monitored_domain_id == b.id, x.hostname) for x in (await db.execute(select(DiscoveredAsset))).scalars().all())
                alerts = (await db.execute(select(SurfaceAlert))).scalars().all()
                certs = sorted(c.hostname for c in (await db.execute(select(SslCertificate))).scalars().all())
                return domains, assets, alerts, certs, b.id

        domains, assets, alerts, certs, b_id = _run(_fresh_engine(), body)
        assert domains == ["b.com"]
        assert [h for _, h in assets] == ["b.com", "shared.com"]
        assert all(x.monitored_domain_id == b_id for x in alerts) and len(alerts) == 2
        assert certs == ["b.com", "shared.com"]  # a.com huerfano borrado; shared.com sigue en uso por b.com
