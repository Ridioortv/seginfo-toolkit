"""Los escaneos anotan que se hizo, sobre que y la huella de la salida cruda del escaner."""
import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app import services
from app.models import ScanStatus, ScannerType


def run_hook(monkeypatch, job):
    calls = []

    async def fake(event_type, **kw):
        calls.append((event_type, kw))
        return True

    monkeypatch.setattr(services.custody, "record_event", fake)
    asyncio.run(services._record_scan_custody(job))
    return calls


def make_job(**kw):
    t0 = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
    base = dict(id="s1", organization_id="org-1", scanner_type=ScannerType.nuclei, target="10.0.0.5", asset_id="as-1",
                status=ScanStatus.completed, findings=[{"t": 1}, {"t": 2}], raw_result="salida cruda", error_message="",
                created_by="ana", started_at=t0, finished_at=t0 + timedelta(seconds=42))
    base.update(kw)
    return SimpleNamespace(**base)


def test_completed_scan_is_recorded_with_output_hash(monkeypatch):
    (event_type, kw), = run_hook(monkeypatch, make_job())
    assert event_type == "scan.completed" and kw["refs"] == ["scan:s1", "asset:as-1"]
    p = kw["payload"]
    assert p["scanner"] == "nuclei" and p["findings"] == 2 and p["duration_seconds"] == 42.0
    assert p["raw_output_sha256"] == services.custody.digest("salida cruda")


def test_failed_scan_is_recorded_as_failed(monkeypatch):
    (event_type, kw), = run_hook(monkeypatch, make_job(status=ScanStatus.failed, error_message="timeout", findings=[]))
    assert event_type == "scan.failed" and kw["payload"]["error"] == "timeout"


def test_broken_job_object_never_raises(monkeypatch):
    assert run_hook(monkeypatch, SimpleNamespace(id="x")) == []
