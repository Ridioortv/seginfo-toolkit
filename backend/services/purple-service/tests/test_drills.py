"""Simulacros medibles: puntaje, ciclo de vida (poner el evento, detectar, reconocer, cerrar, vencer), seguridad del
evento y API. Los otros servicios se reemplazan por un doble de prueba: no hay red."""
import asyncio
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import drills, main
from app.models import Base, PurpleDrill
from backend.shared.database import get_db
from backend.shared.security import create_access_token

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
ORG = "org-1"


def run(coro_fn):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async def go():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            return await coro_fn(factory)
        finally:
            await engine.dispose()

    return asyncio.run(go())


class FakeClients:
    def __init__(self, alerts_created=1, playbooks=None):
        self.rules, self.events, self.alert_list, self.changes = [], [], [], []
        self.alerts_created, self._playbooks = alerts_created, playbooks if playbooks is not None else []
        self.fail = None

    async def ensure_rule(self, org, scenario):
        if self.fail == "rule":
            raise drills.DrillError("HTTP 503")
        self.rules.append((org, scenario))
        return "rule-1"

    async def ingest(self, org, event):
        self.events.append((org, event))
        return self.alerts_created

    async def alerts(self, org, rule_id):
        if self.fail == "alerts":
            raise drills.DrillError("no se pudo conectar (ConnectError)")
        return self.alert_list

    async def status_changes(self, org, alert_id):
        return self.changes

    async def playbooks(self, org):
        return self._playbooks

    def alert_for(self, drill_id, alert_id="al-1", at=NOW):
        self.alert_list = [{"id": alert_id, "created_at": at.isoformat(), "matched_event": {"sentinelops": {"raw": drill_id}}}]

    def change(self, seq, to, minutes, actor="ana@acme.com", notes=""):
        self.changes.append({"seq": seq, "ts": (NOW + timedelta(minutes=minutes)).isoformat(), "actor": actor,
                             "payload": {"to": to, "notes": notes}})


@pytest.fixture(autouse=True)
def custody_log(monkeypatch):
    events = []

    async def fake(event_type, **kw):
        events.append((event_type, kw))
        return True

    monkeypatch.setattr(drills.custody, "record_event", fake)
    return events


# ----------------------------- puntaje -----------------------------

def test_score_bands():
    assert drills.score(True, 600, 3600, True)["score"] == 30 + 40 + 30
    assert drills.score(True, 15 * 60, 4 * 3600, True)["score"] == 100             # justo en el limite
    assert drills.score(True, 16 * 60, 4 * 3600 + 1, True)["score"] == 30 + 30 + 20
    assert drills.score(True, 3601, 25 * 3600, True)["score"] == 30 + 20 + 10
    assert drills.score(True, 5 * 3600, 30 * 3600, True)["score"] == 30 + 10 + 10   # reconocio tarde, cerro muy tarde
    assert drills.score(True, 600, 3600, False)["score"] == 30 + 40 + 15              # cerro sin nota: mitad de puntos
    assert drills.score(True, 600, None, False)["score"] == 30 + 40                  # nunca cerro
    assert drills.score(True, None, None, False)["score"] == 30                      # solo detecto
    assert drills.score(False, None, None, False)["score"] == 0                      # el SIEM no detecto
    assert drills.score(False, 60, 60, True)["score"] == 0                           # sin deteccion no hay reconocimiento valido
    assert [p["key"] for p in drills.score(True, 1, 1, True)["parts"]] == ["detect", "ack", "close"]
    assert sum(p["max"] for p in drills.score(True, 1, 1, True)["parts"]) == 100


def test_rating():
    assert [drills.rating(x) for x in (None, 100, 80, 79, 50, 49, 0)] == ["sin_datos", "preparado", "preparado", "parcial", "parcial", "insuficiente", "insuficiente"]


def test_scenarios_are_complete():
    for key, s in drills.SCENARIOS.items():
        assert s["title"] and s["narrative"] and s["severity"] in ("low", "medium", "high", "critical") and len(s["steps"]) >= 4, key
        assert any("Cerrar la alerta" in x for x in s["steps"])


# ----------------------------- ciclo de vida -----------------------------

def test_start_injects_one_harmless_labeled_event(custody_log):
    fake = FakeClients(playbooks=[{"is_enabled": True, "min_severity": "high"}, {"is_enabled": True, "min_severity": "critical"},
                                  {"is_enabled": False, "min_severity": "low"}])

    async def body(factory):
        async with factory() as db:
            d = await drills.start(db, ORG, "ana@acme.com", "phishing", fake)
            await db.commit()
            return d

    d = run(body)
    assert d.status == "running" and d.detected is True and d.rule_id == "rule-1" and d.injected_at is not None
    assert fake.rules == [(ORG, "phishing")] and len(fake.events) == 1
    ev = fake.events[0][1]
    assert ev["message"].startswith("[SIMULACRO TERO]") and "no hay ningun incidente real" in ev["message"]
    assert ev["raw"] == d.id and ev["event_action"] == "tero_drill:phishing" and ev["host"] == "simulacro-tero"
    assert ev["source_ip"].startswith("192.0.2.")           # rango reservado para documentacion: no es una IP real
    assert d.playbooks_would_respond == 1                    # solo informativo: se cuentan, jamas se ejecutan
    assert [e[0] for e in custody_log] == ["drill.started"]
    assert custody_log[0][1]["payload"]["alert_created"] is True and custody_log[0][1]["subject_id"] == d.id


def test_cannot_start_unknown_scenario_or_two_at_once():
    async def body(factory):
        async with factory() as db:
            with pytest.raises(drills.DrillError, match="desconocido"):
                await drills.start(db, ORG, "a", "no-existe", FakeClients())
            await drills.start(db, ORG, "a", "phishing", FakeClients())
            with pytest.raises(drills.DrillError, match="en curso"):
                await drills.start(db, ORG, "a", "ransomware", FakeClients())
            # otra organizacion si puede
            await drills.start(db, "org-2", "b", "ransomware", FakeClients())

    run(body)


def test_siem_failure_on_start_is_reported_as_error():
    fake = FakeClients()
    fake.fail = "rule"

    async def body(factory):
        async with factory() as db:
            with pytest.raises(drills.DrillError, match="SIEM"):
                await drills.start(db, ORG, "a", "phishing", fake)

    run(body)


def test_no_alert_means_not_detected_and_zero(custody_log):
    fake = FakeClients(alerts_created=0)

    async def body(factory):
        async with factory() as db:
            d = await drills.start(db, ORG, "a", "phishing", fake)
            assert d.detected is False
            d.injected_at = NOW - timedelta(hours=25)
            await drills.step(db, d, fake, NOW)
            return d

    d = run(body)
    assert d.status == "expired" and d.score == 0 and d.result["rating"] == "insuficiente" and d.result["detected"] is False
    assert custody_log[-1][0] == "drill.completed" and custody_log[-1][1]["payload"]["status"] == "expired"


def test_full_flow_measures_ack_and_close_from_the_chain(custody_log):
    fake = FakeClients()

    async def body(factory):
        async with factory() as db:
            d = await drills.start(db, ORG, "ana@acme.com", "ransomware", fake)
            d.injected_at = NOW
            fake.alert_for(d.id, at=NOW + timedelta(seconds=2))
            assert await drills.step(db, d, fake, NOW + timedelta(minutes=1)) == "running"
            assert d.alert_id == "al-1" and d.acked_at is None
            fake.change(1, "acknowledged", 10, "luis@acme.com")
            assert await drills.step(db, d, fake, NOW + timedelta(minutes=11)) == "running"
            assert d.acked_by == "luis@acme.com"
            fake.change(2, "closed", 90, "luis@acme.com", notes="Aislamos el servidor y avisamos a direccion")
            assert await drills.step(db, d, fake, NOW + timedelta(minutes=91)) == "completed"
            await db.commit()
            return d

    d = run(body)
    r = d.result
    assert abs(r["ack_seconds"] - (10 * 60 - 2)) < 1 and abs(r["close_seconds"] - (90 * 60 - 2)) < 1
    assert r["detected"] and r["note_ok"] and r["score"] == 100 and r["rating"] == "preparado"
    assert r["acked_by"] == "luis@acme.com" and r["detect_seconds"] == 2.0
    done = [e for e in custody_log if e[0] == "drill.completed"]
    assert len(done) == 1
    p = done[0][1]["payload"]
    assert p["score"] == 100 and p["thresholds"]["points"] == drills.POINTS and p["ack_seconds"] == r["ack_seconds"]
    assert f"alert:al-1" in done[0][1]["refs"] and done[0][1]["subject_id"] == d.id


def test_close_without_note_gets_half_the_closing_points():
    fake = FakeClients()

    async def body(factory):
        async with factory() as db:
            d = await drills.start(db, ORG, "a", "fuerza_bruta", fake)
            d.injected_at = NOW
            fake.alert_for(d.id)
            fake.change(1, "closed", 5, notes="ok")          # nota demasiado corta
            await drills.step(db, d, fake, NOW + timedelta(minutes=6))
            return d

    d = run(body)
    assert d.status == "completed" and d.result["note_ok"] is False and d.score == 30 + 40 + 15


def test_alert_from_another_drill_is_not_matched_and_client_errors_keep_it_running():
    fake = FakeClients()

    async def body(factory):
        async with factory() as db:
            d = await drills.start(db, ORG, "a", "phishing", fake)
            fake.alert_for("otro-simulacro")
            await drills.step(db, d, fake, NOW)
            assert d.alert_id is None
            fake.fail = "alerts"
            assert await drills.step(db, d, fake, NOW) == "running"
            assert "ConnectError" in d.last_error
            fake.fail = None
            await drills.step(db, d, fake, NOW)
            assert d.last_error == ""
            return d

    run(body)


def test_expires_after_24_hours_with_what_happened():
    fake = FakeClients()

    async def body(factory):
        async with factory() as db:
            d = await drills.start(db, ORG, "a", "phishing", fake)
            d.injected_at = NOW - timedelta(hours=23)
            fake.alert_for(d.id, at=NOW - timedelta(hours=23))
            fake.change(1, "acknowledged", -22 * 60)
            assert await drills.step(db, d, fake, NOW) == "running"
            assert await drills.step(db, d, fake, NOW + timedelta(hours=2)) == "expired"
            return d

    d = run(body)
    assert d.score == 30 + 30 and d.result["close_seconds"] is None   # reconocio a la hora justa (30 pts), nunca cerro


def test_cancel_records_and_frees_the_slot(custody_log):
    fake = FakeClients()

    async def body(factory):
        async with factory() as db:
            d = await drills.start(db, ORG, "a", "phishing", fake)
            await drills.cancel(db, d, "ana")
            assert d.status == "cancelled"
            await drills.start(db, ORG, "a", "ransomware", fake)     # ya se puede empezar otro
            return d

    run(body)
    assert "drill.cancelled" in [e[0] for e in custody_log]


def test_stats():
    fake = FakeClients()

    async def body(factory):
        async with factory() as db:
            for i, (mins, close) in enumerate([(5, 30), (20, 200), (70, None)]):
                d = await drills.start(db, ORG, "a", "phishing", fake)
                d.injected_at = NOW - timedelta(days=10 * (3 - i))
                fake.alert_for(d.id, at=d.injected_at)
                fake.changes = []
                fake.change(1, "acknowledged", mins)
                for c in fake.changes:
                    c["ts"] = (d.injected_at + timedelta(minutes=mins)).isoformat()
                if close:
                    fake.change(2, "closed", close, notes="Se resolvio como corresponde")
                    fake.changes[-1]["ts"] = (d.injected_at + timedelta(minutes=close)).isoformat()
                await drills.step(db, d, fake, NOW - timedelta(days=10 * (3 - i)) + timedelta(hours=30 if not close else 1))
            assert (await drills.stats(db, "otra-org", NOW))["completed_total"] == 0
            return await drills.stats(db, ORG, NOW)

    s = run(body)
    assert s["completed_total"] == 3 and s["completed_last_90_days"] == 3 and s["running"] is None
    assert s["scenarios_done"] == ["phishing"] and len(s["history"]) == 3
    assert s["last_score"] is not None and s["average_score_last5"] is not None
    assert s["median_ack_seconds"] == 20 * 60 and s["days_since_last"] >= 0


# ----------------------------- API -----------------------------

def tok(role="admin", org=ORG, email="ana@acme.com"):
    return {"Authorization": "Bearer " + create_access_token("u1", role, org_id=org, email=email)}


@pytest.fixture()
def client(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(prefix="drill-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")

    async def init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(init())
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override():
        async with Session() as s:
            yield s

    fake = FakeClients()
    monkeypatch.setattr(drills, "get_clients", lambda: fake)
    main.app.dependency_overrides[get_db] = override
    c = TestClient(main.app)
    c.fake = fake
    yield c
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def test_api_roles_and_flow(client):
    assert client.get("/drills").status_code == 401
    assert client.get("/drills/scenarios", headers=tok("viewer")).status_code == 200
    assert client.post("/drills", json={"scenario": "phishing"}, headers=tok("analyst")).status_code == 403
    assert client.post("/drills", json={"scenario": "nada"}, headers=tok()).status_code == 422
    r = client.post("/drills", json={"scenario": "phishing"}, headers=tok("soc_manager"))
    assert r.status_code == 201
    d = r.json()
    assert d["status"] == "running" and d["steps"] and d["result"]["detected"] is True
    assert client.post("/drills", json={"scenario": "ransomware"}, headers=tok()).status_code == 409
    client.fake.alert_for(d["id"])
    client.fake.change(1, "closed", 3, notes="Resuelto: se confirmo con el usuario y se cambio la clave")
    got = client.get(f"/drills/{d['id']}", headers=tok("viewer")).json()
    assert got["status"] == "completed" and got["score"] == 100
    assert client.get("/drills/stats", headers=tok("viewer")).json()["completed_total"] == 1
    assert len(client.get("/drills", headers=tok("viewer")).json()) == 1


def test_api_org_isolation_and_cancel(client):
    d = client.post("/drills", json={"scenario": "phishing"}, headers=tok()).json()
    assert client.get(f"/drills/{d['id']}", headers=tok(org="org-2")).status_code == 404
    assert client.post(f"/drills/{d['id']}/cancel", headers=tok(org="org-2")).status_code == 404
    assert client.get("/drills", headers=tok(org="org-2")).json() == []
    assert client.post(f"/drills/{d['id']}/cancel", headers=tok("analyst")).status_code == 403
    assert client.post(f"/drills/{d['id']}/cancel", headers=tok()).json()["status"] == "cancelled"


def test_api_siem_down_is_502_and_nothing_is_left_running(client):
    client.fake.fail = "rule"
    assert client.post("/drills", json={"scenario": "phishing"}, headers=tok()).status_code == 502
    client.fake.fail = None
    assert client.post("/drills", json={"scenario": "phishing"}, headers=tok()).status_code == 201
