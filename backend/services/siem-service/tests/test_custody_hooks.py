"""Las alertas anotan su creacion y cada cambio de estado en la cadena de custodia (sin copiar el evento crudo)."""
import asyncio
from types import SimpleNamespace

from app import services
from app.models import AlertStatus, RuleSeverity


class FakeDb:
    def add(self, obj):
        obj.id = obj.id or "al-1"

    async def flush(self):
        pass

    async def refresh(self, obj):
        pass


def capture(monkeypatch):
    calls = []

    async def fake(event_type, **kw):
        calls.append((event_type, kw))
        return True

    monkeypatch.setattr(services.custody, "record_event", fake)
    return calls


def test_event_summary_keeps_only_identifying_fields():
    ev = {"host": {"name": "srv1"}, "user": {"name": ""}, "source": {"ip": "10.0.0.5"}, "destination": {"ip": ""},
          "event": {"action": "login_failed"}, "@timestamp": "2026-10-01T00:00:00Z", "message": "contrasena=secreta"}
    out = services.event_summary(ev)
    assert out == {"host": "srv1", "source_ip": "10.0.0.5", "action": "login_failed", "event_time": "2026-10-01T00:00:00Z"}
    assert "secreta" not in str(out)


def test_create_alert_records_hash_not_the_raw_event(monkeypatch):
    calls = capture(monkeypatch)
    rule = SimpleNamespace(id="r1", name="SSH brute", severity=RuleSeverity.high)
    event = {"host": {"name": "srv1"}, "message": "contrasena=secreta"}
    alert = asyncio.run(services._create_alert(FakeDb(), rule, event, "org-1"))
    (event_type, kw), = calls
    assert event_type == "alert.created" and kw["organization_id"] == "org-1"
    assert kw["subject_id"] == alert.id and kw["refs"] == [f"alert:{alert.id}"]
    assert kw["payload"]["event_sha256"] == services.custody.digest(event)
    assert "secreta" not in str(kw["payload"]) and kw["payload"]["severity"] == "high"


def test_update_alert_records_status_change(monkeypatch):
    calls = capture(monkeypatch)
    alert = SimpleNamespace(id="al-9", organization_id="org-1", rule_name="SSH brute", status=AlertStatus.new,
                            notes="", acknowledged_by="")
    payload = SimpleNamespace(status=AlertStatus.acknowledged, notes="Lo reviso Ana")
    asyncio.run(services.update_alert(FakeDb(), alert, payload, "ana@acme.com"))
    (event_type, kw), = calls
    assert event_type == "alert.status_changed" and kw["actor"] == "ana@acme.com"
    assert kw["payload"]["from"] == "new" and kw["payload"]["to"] == "acknowledged"
    assert kw["payload"]["notes"] == "Lo reviso Ana" and kw["refs"] == ["alert:al-9"]
