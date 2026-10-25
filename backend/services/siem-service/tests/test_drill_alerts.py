"""Las alertas de los simulacros de TERO (regla con la etiqueta tero-drill) nunca disparan respuesta automatica
real ni consultan inteligencia de amenazas; las alertas normales siguen igual. Y /alerts se puede filtrar por regla."""
import asyncio
from types import SimpleNamespace

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import services
from app.models import Base, RuleSeverity, SigmaRule


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


def payload(action, org="o1"):
    return SimpleNamespace(organization_id=org, events=[SimpleNamespace(model_dump=lambda: {
        "host": "h", "event_action": action, "message": "m", "raw": "d-1", "source_ip": "192.0.2.10"})])


def test_drill_alert_skips_soar_and_threat_intel_but_normal_alert_does_not(monkeypatch):
    soar, intel = [], []

    async def fake_soar(alert, org, tags=None):
        soar.append(alert.rule_name)
        return True

    async def fake_intel(alert, event):
        intel.append(alert.rule_name)

    async def fake_index(client, doc):
        return None

    async def fake_custody(*a, **k):
        return True

    monkeypatch.setattr(services, "_notify_soar", fake_soar)
    monkeypatch.setattr(services, "_enrich_alert_with_threat_intel", fake_intel)
    monkeypatch.setattr(services.opensearch_client, "index_event", fake_index)
    monkeypatch.setattr(services.custody, "record_event", fake_custody)

    async def body(factory):
        async with factory() as db:
            drill = SigmaRule(organization_id="o1", name="[SIMULACRO] x", severity=RuleSeverity.high, tags=["tero-drill", "tero-drill:phishing"],
                              detection={"selection": {"event.action": "tero_drill:phishing"}, "condition": "selection"})
            normal = SigmaRule(organization_id="o1", name="Login raro", severity=RuleSeverity.high, tags=["attack.t1110"],
                               detection={"selection": {"event.action": "login_failed"}, "condition": "selection"})
            db.add_all([drill, normal])
            await db.commit()
            _, n1 = await services.ingest_events(db, None, payload("tero_drill:phishing"))
            _, n2 = await services.ingest_events(db, None, payload("login_failed"))
            await db.commit()
            by_rule = await services.list_alerts(db, "o1", rule_id=drill.id)
            allalerts = await services.list_alerts(db, "o1")
            other_org = await services.list_alerts(db, "o2", rule_id=drill.id)
            return n1, n2, by_rule, allalerts, other_org, drill.id

    n1, n2, by_rule, allalerts, other_org, drill_id = run(body)
    assert n1 == 1 and n2 == 1
    assert soar == ["Login raro"] and intel == ["Login raro"]   # el simulacro no llego a SOAR ni a inteligencia externa
    assert len(by_rule) == 1 and by_rule[0].rule_id == drill_id and by_rule[0].soar_triggered is False
    assert len(allalerts) == 2 and other_org == []


def test_is_drill_rule_matches_tag_case_insensitively():
    assert services.is_drill_rule(SimpleNamespace(tags=["TERO-Drill"]))
    assert not services.is_drill_rule(SimpleNamespace(tags=["attack.t1110"]))
    assert not services.is_drill_rule(SimpleNamespace(tags=None))
