"""Cada cambio de estado de una vulnerabilidad queda en la cadena de custodia."""
import asyncio
from types import SimpleNamespace

from app import services
from app.models import VulnSeverity, VulnStatus


class FakeDb:
    async def flush(self):
        pass

    async def refresh(self, obj):
        pass


def test_triage_records_before_and_after(monkeypatch):
    calls = []

    async def fake(event_type, **kw):
        calls.append((event_type, kw))
        return True

    monkeypatch.setattr(services.custody, "record_event", fake)
    vuln = SimpleNamespace(id="v1", organization_id="org-1", asset_id="as-1", title="OpenSSH viejo", cve_id="CVE-2024-6387",
                           severity=VulnSeverity.high, status=VulnStatus.open, triage_note="", triaged_by="", updated_at=None)
    asyncio.run(services.triage_vulnerability(FakeDb(), vuln, SimpleNamespace(status=VulnStatus.remediated, note="Actualizado"), "ana"))
    (event_type, kw), = calls
    assert event_type == "vuln.status_changed" and kw["organization_id"] == "org-1"
    assert kw["refs"] == ["vuln:v1", "asset:as-1"]
    assert kw["payload"]["from"] == "open" and kw["payload"]["to"] == "remediated" and kw["payload"]["cve"] == "CVE-2024-6387"
