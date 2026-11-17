"""Cada corrida de playbook (real o simulada) queda en la cadena de custodia con el resultado de cada paso."""
import asyncio
from types import SimpleNamespace

from app import services
from app.models import PlaybookRun


class FakeDb:
    def add(self, obj):
        obj.id = obj.id or "run-1"

    async def flush(self):
        pass

    async def refresh(self, obj):
        pass


def test_playbook_run_is_recorded_with_steps(monkeypatch):
    calls = []

    async def fake(event_type, **kw):
        calls.append((event_type, kw))
        return True

    monkeypatch.setattr(services.custody, "record_event", fake)
    playbook = SimpleNamespace(id="pb1", name="Bloquear IP", steps=[{"action": "accion_inexistente"}])
    context = {"organization_id": "org-1", "alert": {"id": "al-7"}}
    run = asyncio.run(services._run_steps(FakeDb(), playbook, context, "siem-service"))
    (event_type, kw), = calls
    assert event_type == "soar.playbook_run" and kw["organization_id"] == "org-1"
    assert kw["refs"] == [f"run:{run.id}", "alert:al-7"] and kw["subject_type"] == "playbook_run"
    assert kw["payload"]["status"] == "failed" and kw["payload"]["playbook"] == "Bloquear IP"
    assert kw["payload"]["steps"][0]["action"] == "accion_inexistente" and kw["payload"]["steps"][0]["success"] is False
