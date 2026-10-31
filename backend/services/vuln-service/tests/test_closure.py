"""Cierre verificado: repetir el escaneo, decidir (verificado / fallo / inconcluso / no soportado), quedar en la
cadena de custodia, no duplicar la vulnerabilidad y medir el MTTR real."""
import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import closure, main as vuln_main, services
from app.models import Base, VulnSeverity, VulnStatus, Vulnerability
from app.schemas import FindingIn, IngestRequest, TriageRequest

ORG = "org-1"
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


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


class FakeScan:
    """Simula scan-service: guarda los jobs creados y devuelve el estado que el test decida."""

    def __init__(self, original=None, rescan=None, fail_create=0):
        self.original = original
        self.rescan = rescan or {"id": "job-new", "status": "completed", "findings": [], "scanner_type": "nuclei",
                                 "target": "http://app.cliente.com", "finished_at": "2026-10-20T11:59:00Z", "error_message": ""}
        self.created, self.fail_create = [], fail_create

    async def get_job(self, org, job_id):
        if job_id == "job-new":
            return self.rescan
        return self.original if job_id == "job-old" else None

    async def create_job(self, org, payload):
        if self.fail_create:
            self.fail_create -= 1
            raise closure.ClosureError("scan-service no responde")
        self.created.append(payload)
        return {"id": "job-new"}


ORIGINAL = {"id": "job-old", "scanner_type": "nuclei", "target": "http://app.cliente.com", "options": {"severity": "high"},
            "status": "completed", "findings": []}


@pytest.fixture(autouse=True)
def custody_log(monkeypatch):
    events = []

    async def fake(event_type, **kw):
        events.append((event_type, kw))
        return True

    monkeypatch.setattr(closure.custody, "record_event", fake)
    monkeypatch.setattr(services.custody, "record_event", fake)
    return events


async def make_vuln(db, **kw):
    base = dict(organization_id=ORG, title="Panel expuesto", cve_id="CVE-2024-0001", severity=VulnSeverity.high,
                source_scanner="nuclei", scan_job_id="job-old", asset_id="as-1", status=VulnStatus.open,
                created_at=NOW - timedelta(hours=48))
    base.update(kw)
    v = Vulnerability(**base)
    db.add(v)
    await db.flush()
    return v


async def remediate(db, v):
    await services.triage_vulnerability(db, v, TriageRequest(status=VulnStatus.remediated, note="parcheado"), "ana")


def test_remediating_starts_a_pending_verification(custody_log):
    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db)
            await remediate(db, v)
            return v.closure_status, v.remediated_at is not None, v.verified_at

    assert run(body) == ("pending", True, None)


def test_reopening_a_remediated_vuln_clears_the_closure(custody_log):
    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db)
            await remediate(db, v)
            await services.triage_vulnerability(db, v, TriageRequest(status=VulnStatus.confirmed), "ana")
            return v.closure_status, v.remediated_at

    assert run(body) == ("", None)


def test_verified_when_the_rescan_no_longer_finds_it(custody_log):
    scan = FakeScan(original=ORIGINAL)

    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db)
            await remediate(db, v)
            assert await closure.step(db, v, scan, NOW) == "pending"       # paso 1: pide el re-escaneo
            assert scan.created[0]["target"] == "http://app.cliente.com" and scan.created[0]["options"] == {"severity": "high"}
            assert scan.created[0]["scanner_type"] == "nuclei" and scan.created[0]["asset_id"] == "as-1"
            assert await closure.step(db, v, scan, NOW + timedelta(minutes=5)) == "verified"  # paso 2: lo evalua
            return v

    v = run(body)
    assert v.status == VulnStatus.remediated and v.verified_at is not None
    types = [e[0] for e in custody_log]
    assert types == ["vuln.status_changed", "vuln.closure_requested", "vuln.closure_verified"]
    payload = custody_log[-1][1]["payload"]
    assert payload["closure_scan_job_id"] == "job-new" and payload["mttr_real_hours"] >= 0 and payload["scan_total_findings"] == 0
    assert "scan:job-new" in custody_log[-1][1]["refs"] and "vuln:" + v.id in custody_log[-1][1]["refs"]


def test_failed_reopens_and_is_recorded(custody_log):
    scan = FakeScan(original=ORIGINAL, rescan={"id": "job-new", "status": "completed", "scanner_type": "nuclei", "target": "t",
                                               "finished_at": "x", "error_message": "",
                                               "findings": [{"cve_id": "CVE-2024-0001", "title": "otra cosa"}, {"cve_id": "CVE-9", "title": "z"}]})

    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db)
            await remediate(db, v)
            await closure.step(db, v, scan, NOW)
            return v, await closure.step(db, v, scan, NOW)

    v, state = run(body)
    assert state == "failed" and v.status == VulnStatus.open and v.verified_at is None
    assert "Reabierta" in v.triage_note and v.triaged_by == closure.SYSTEM_ACTOR
    assert custody_log[-1][0] == "vuln.closure_failed" and custody_log[-1][1]["payload"]["matches"] == 1


def test_scan_that_failed_or_never_finished_is_never_verified(custody_log):
    def go(rescan, hours=0.1):
        scan = FakeScan(original=ORIGINAL, rescan=rescan)

        async def body(factory):
            async with factory() as db:
                v = await make_vuln(db)
                await remediate(db, v)
                await closure.step(db, v, scan, NOW)
                await closure.step(db, v, scan, NOW + timedelta(hours=hours))
                return v

        return run(body)

    v = go({"id": "job-new", "status": "failed", "error_message": "nuclei no pudo conectar", "findings": []})
    assert v.closure_status == "inconclusive" and "nuclei no pudo conectar" in v.closure_detail and v.verified_at is None
    v = go({"id": "job-new", "status": "running", "findings": []})
    assert v.closure_status == "pending"
    v = go({"id": "job-new", "status": "running", "findings": []}, hours=closure.TIMEOUT_HOURS + 1)
    assert v.closure_status == "inconclusive" and "no termino" in v.closure_detail
    assert not any(e[0] == "vuln.closure_verified" for e in custody_log)


def test_unsupported_cases(custody_log):
    cases = [
        (dict(scan_job_id=None, source_scanner="cloud"), None, "nube"),
        (dict(), None, "ya no existe"),
        (dict(), {**ORIGINAL, "options": {"mode": "upload"}}, "archivo subido"),
        (dict(), {**ORIGINAL, "scanner_type": "falco"}, "tipo de escaner"),
    ]
    for kw, original, expect in cases:
        scan = FakeScan(original=original)

        async def body(factory):
            async with factory() as db:
                v = await make_vuln(db, **kw)
                await remediate(db, v)
                await closure.step(db, v, scan, NOW)
                return v

        v = run(body)
        assert v.closure_status == "unsupported" and expect in v.closure_detail, (kw, v.closure_detail)
        assert v.status == VulnStatus.remediated and scan.created == []


def test_create_errors_retry_then_give_up(custody_log):
    scan = FakeScan(original=ORIGINAL, fail_create=5)

    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db)
            await remediate(db, v)
            states = [await closure.step(db, v, scan, NOW) for _ in range(3)]
            return states, v

    states, v = run(body)
    assert states == ["pending", "pending", "inconclusive"] and "Podes reintentar" in v.closure_detail


def test_finding_matching_rules():
    cve = SimpleNamespace(cve_id="CVE-2024-0001", package="openssl", title="x")
    assert closure.finding_matches(cve, {"cve_id": "cve-2024-0001", "package": "openssl"})
    assert not closure.finding_matches(cve, {"cve_id": "CVE-2024-0001", "package": "zlib"})
    assert closure.finding_matches(cve, {"cve_id": "CVE-2024-0001"})
    assert not closure.finding_matches(cve, {"cve_id": "CVE-2024-0002", "package": "openssl"})
    no_cve = SimpleNamespace(cve_id=None, package="", title="Panel expuesto")
    assert closure.finding_matches(no_cve, {"title": "Panel expuesto"})
    assert not closure.finding_matches(no_cve, {"title": "Panel expuesto", "cve_id": "CVE-1"})
    assert not closure.finding_matches(no_cve, {"title": "Otro"})


def test_ingest_during_verification_does_not_duplicate(custody_log, monkeypatch):
    async def no_asset(asset_id, org):
        return "medium"

    monkeypatch.setattr(services, "_get_asset_criticality", no_asset)

    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db, cve_id=None, title="Panel expuesto")
            await remediate(db, v)
            payload = IngestRequest(scan_job_id="job-new", asset_id="as-1", scanner_type="nuclei",
                                    findings=[FindingIn(title="Panel expuesto", severity="high")])
            created, updated = await services.ingest_findings(db, payload, ORG)
            total = len((await db.execute(select(Vulnerability))).scalars().all())
            return created, updated, total

    assert run(body) == (0, 1, 1)


def test_verified_vulnerability_that_comes_back_is_a_new_record(custody_log, monkeypatch):
    async def no_asset(asset_id, org):
        return "medium"

    monkeypatch.setattr(services, "_get_asset_criticality", no_asset)

    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db, cve_id=None, title="Panel expuesto", closure_status="verified", status=VulnStatus.remediated)
            payload = IngestRequest(scan_job_id="job-9", asset_id="as-1", scanner_type="nuclei",
                                    findings=[FindingIn(title="Panel expuesto", severity="high")])
            return await services.ingest_findings(db, payload, ORG)

    assert run(body) == (1, 0)


def test_stats_real_vs_declared_mttr(custody_log):
    async def body(factory):
        async with factory() as db:
            # verificada: detectada hace 48 h, declarada remediada a las 10 h, verificada a las 24 h
            t0 = NOW - timedelta(hours=48)
            await make_vuln(db, title="A", created_at=t0, status=VulnStatus.remediated, remediated_at=t0 + timedelta(hours=10),
                            closure_status="verified", verified_at=t0 + timedelta(hours=24))
            # declarada y nunca verificada (no soportada): 20 h
            await make_vuln(db, title="B", created_at=t0, status=VulnStatus.remediated, remediated_at=t0 + timedelta(hours=20),
                            closure_status="unsupported")
            # cierre que fallo: se reabrio
            await make_vuln(db, title="C", created_at=t0, status=VulnStatus.open, closure_status="failed", severity=VulnSeverity.critical)
            await make_vuln(db, title="D", created_at=t0, status=VulnStatus.remediated, remediated_at=t0 + timedelta(hours=2),
                            closure_status="pending")
            await make_vuln(db, title="E", status=VulnStatus.open)  # no cuenta
            return await closure.stats(db, ORG)

    s = run(body)
    assert s["counts"] == {"pending": 1, "verified": 1, "failed": 1, "inconclusive": 0, "unsupported": 1}
    assert s["remediated_total"] == 3 and s["remediated_unverified"] == 1
    assert s["mttr_real_hours"] == 24.0 and s["mttr_declared_hours"] == round((10 + 20 + 2) / 3, 2)
    assert s["false_closure_rate_pct"] == 50.0
    assert s["by_severity"]["high"]["verified"] == 1 and s["by_severity"]["critical"]["failed"] == 1


def test_process_pending_loop_advances_and_isolates_errors(custody_log):
    scan = FakeScan(original=ORIGINAL)

    async def body(factory):
        async with factory() as db:
            ok = await make_vuln(db, title="ok")
            await remediate(db, ok)
            await db.commit()
        first = await closure.process_pending(factory, scan)
        second = await closure.process_pending(factory, scan)
        async with factory() as db:
            rows = (await db.execute(select(Vulnerability))).scalars().all()
        return first, second, [r.closure_status for r in rows]

    assert run(body) == (1, 1, ["verified"])


def test_verify_closure_endpoint(custody_log, monkeypatch):
    scan = FakeScan(original=ORIGINAL)
    monkeypatch.setattr(closure, "get_client", lambda: scan)
    claims = {"sub": "u", "org_id": ORG, "role": "analyst", "email": "ana@x.com"}

    async def body(factory):
        from fastapi import HTTPException
        async with factory() as db:
            open_v = await make_vuln(db, title="abierta")
            done = await make_vuln(db, title="hecha")
            await remediate(db, done)
            other = await make_vuln(db, title="ajena", organization_id="otra")
            await db.commit()
            ids = (open_v.id, done.id, other.id)
        results = {}
        for name, vid in zip(("open", "done", "other"), ids):
            async with factory() as db:
                try:
                    out = await vuln_main.verify_closure(vid, claims=claims, db=db)
                    results[name] = (200, out.closure_status, out.closure_scan_job_id)
                except HTTPException as exc:
                    results[name] = (exc.status_code,)
        async with factory() as db:
            try:
                await vuln_main.verify_closure(ids[1], claims=claims, db=db)
            except HTTPException as exc:
                results["again"] = (exc.status_code,)
        return results

    r = run(body)
    assert r["open"] == (409,) and r["other"] == (404,)
    assert r["done"] == (200, "pending", "job-new") and r["again"] == (409,)


def test_hours_between_handles_naive_and_missing():
    assert closure.hours_between(None, NOW) is None
    assert closure.hours_between(datetime(2026, 10, 20, 0, 0), NOW) == 12.0
    assert closure.hours_between(NOW, NOW - timedelta(hours=1)) == 0.0


def test_auto_verify_can_be_turned_off(monkeypatch, custody_log):
    monkeypatch.setenv("VULN_AUTO_VERIFY_CLOSURE", "false")

    async def body(factory):
        async with factory() as db:
            v = await make_vuln(db)
            await remediate(db, v)
            return v.closure_status

    assert run(body) == "unsupported"
