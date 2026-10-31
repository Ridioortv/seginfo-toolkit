"""Integracion AntiEstafa AR: el aviso (JSON tipo ECS) entra por /integrations/antiestafa/events, se convierte campo por
campo, dispara las reglas Sigma de la integracion, abre alertas (que siguen a SOAR) y detecta campanas repetidas."""
import asyncio
import copy
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app import antiestafa, services
from app.models import Base, SigmaRule

EVENT = {
    "@timestamp": "2026-10-25T19:00:00.000Z",
    "event": {"kind": "alert", "category": ["threat"], "module": "antiestafa", "dataset": "antiestafa.analisis",
              "provider": "AntiEstafa AR", "severity": 92, "outcome": "estafa"},
    "message": "AntiEstafa: estafa (riesgo 92/100) en mensaje · mercadopag0-seguridad.example",
    "organization": {"id": "acme-sa"},
    "threat": {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0001", "name": "Initial Access"},
               "technique": [{"id": "T1566", "name": "Phishing", "subtechnique": [{"id": "T1566.002", "name": "Spearphishing Link"}]},
                             {"id": "T1598", "name": "Phishing for Information"}]},
    "tags": ["antiestafa", "attack.t1566"],
    "antiestafa": {"veredicto": "estafa", "score": 92, "canal": "mensaje",
                   "banderas": ["Imita a Mercado Pago", "Te pide el código de verificación"],
                   "dominios": ["mercadopag0-seguridad.example"], "sin_ia": False, "huella": "2d711642b726b044"},
}


def ev(**changes):
    e = copy.deepcopy(EVENT)
    ae = changes.pop("ae", {})
    e["antiestafa"].update(ae)
    for k, v in changes.items():
        if k == "outcome":
            e["event"]["outcome"] = v
        else:
            e[k] = v
    return e


# ------------------------------------------------------------------ conversion

def test_build_document_keeps_only_expected_fields():
    raw = ev()
    raw["evil"] = {"x": "y"}
    raw["antiestafa"]["extra"] = "no"
    doc = antiestafa.build_document(raw, "acme-sa")
    assert "evil" not in doc and "extra" not in doc["antiestafa"]
    assert doc["organization_id"] == "acme-sa"
    assert doc["event"]["module"] == "antiestafa" and doc["event"]["outcome"] == "estafa"
    assert doc["antiestafa"]["dominios"] == ["mercadopag0-seguridad.example"]
    assert doc["antiestafa"]["huella"] == "2d711642b726b044"
    assert [t["id"] for t in doc["threat"]["technique"]] == ["T1566", "T1598"]
    assert doc["sentinelops"]["source_type"] == "antiestafa" and doc["sentinelops"]["severity"] == "high"
    assert "texto" not in doc["antiestafa"]  # por defecto no se guarda el texto


def test_audio_scam_is_critical_and_text_only_if_sent():
    doc = antiestafa.build_document(ev(ae={"canal": "audio", "transcripcion": "hola soy el gerente"}), "o")
    assert doc["sentinelops"]["severity"] == "critical" and doc["antiestafa"]["transcripcion"] == "hola soy el gerente"


@pytest.mark.parametrize("bad", [
    {"event": {"module": "otro", "outcome": "estafa"}},
    {"event": {"module": "antiestafa", "outcome": "campana"}},   # la campana solo la genera TERO
    {"event": {"module": "antiestafa", "outcome": "seguro"}},
    {},
])
def test_build_document_rejects_foreign_events(bad):
    with pytest.raises(antiestafa.AntiEstafaError):
        antiestafa.build_document(bad, "o")


def test_hostile_values_are_cleaned():
    doc = antiestafa.build_document(ev(ae={"dominios": ["OK.example", "<script>", "a" * 400, {"x": 1}], "banderas": ["x" * 999] * 50,
                                           "canal": "otro-canal", "score": "abc"}), "o")
    assert doc["antiestafa"]["dominios"] == ["ok.example"]
    assert len(doc["antiestafa"]["banderas"]) == 1 and len(doc["antiestafa"]["banderas"][0]) == 200
    assert doc["antiestafa"]["canal"] == "otro" and doc["antiestafa"]["score"] == 0


def test_future_timestamp_is_clamped_and_org_validated():
    doc = antiestafa.build_document(ev(**{"@timestamp": "2999-01-01T00:00:00Z"}), "o")
    assert doc["@timestamp"] < "2999"
    with pytest.raises(antiestafa.AntiEstafaError):
        antiestafa.org_from_event({"organization": {"id": "../x y"}})
    assert antiestafa.org_from_event({}) is None


def test_test_events_are_recognised():
    assert antiestafa.is_test_event({"message": "[PRUEBA] conexion"})
    assert antiestafa.is_test_event({"message": "x", "labels": {"prueba": "true"}})
    assert not antiestafa.is_test_event(EVENT)


# ------------------------------------------------------------------ reglas (con el motor Sigma real)

def matches(doc):
    from app.sigma import evaluate_rule
    return [r["name"] for r in antiestafa.RULES if evaluate_rule(doc, r["detection"])]


def test_each_event_matches_exactly_one_rule():
    scam = antiestafa.build_document(ev(), "o")
    maybe = antiestafa.build_document(ev(outcome="sospechoso"), "o")
    voice = antiestafa.build_document(ev(ae={"canal": "audio"}), "o")
    camp = antiestafa.campaign_document("o", "dominio:x.example", 3)
    assert matches(scam) == [antiestafa.RULE_NAMES[0]]
    assert matches(maybe) == [antiestafa.RULE_NAMES[1]]
    assert matches(voice) == [antiestafa.RULE_NAMES[2]]   # un audio no abre dos alertas
    assert matches(camp) == [antiestafa.RULE_NAMES[3]]


def test_rules_carry_attack_tags_for_coverage():
    import re
    tags = {t for r in antiestafa.RULES for t in r["tags"]}
    assert "attack.t1566" in tags and re.search(r"attack\.(t\d{4})", "attack.t1566")
    assert all(r["detection"]["condition"] for r in antiestafa.RULES)


# ------------------------------------------------------------------ endpoint de punta a punta

@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("SIEM_INGEST_TOKEN", "master-token-master-token")
    import app.main as m
    from backend.shared.database import get_db
    from backend.shared.ingest_auth import org_ingest_token

    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})

    async def init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(init())
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override():
        async with factory() as session:
            yield session

    soar, indexed = [], []

    async def fake_soar(alert, org, tags=None):
        soar.append((alert.rule_name, org))
        return True

    async def fake_intel(alert, event):
        return None

    async def fake_index(client, doc):
        indexed.append(doc)

    async def fake_custody(*a, **k):
        return True

    monkeypatch.setattr(services, "_notify_soar", fake_soar)
    monkeypatch.setattr(services, "_enrich_alert_with_threat_intel", fake_intel)
    monkeypatch.setattr(services.opensearch_client, "index_event", fake_index)
    monkeypatch.setattr(services.custody, "record_event", fake_custody)
    antiestafa.LAST_SEEN.clear()
    m.app.dependency_overrides[get_db] = override
    client = TestClient(m.app)
    token = org_ingest_token("acme-sa")

    class Ctx:
        pass

    c = Ctx()
    c.client, c.token, c.soar, c.indexed, c.factory, c.m = client, token, soar, indexed, factory, m
    yield c
    m.app.dependency_overrides.pop(get_db, None)
    asyncio.run(engine.dispose())


def seed(c, org="acme-sa"):
    async def go():
        async with c.factory() as db:
            created = await antiestafa.seed_rules(db, org)
            await db.commit()
            return len(created)
    return asyncio.run(go())


def post(c, body, token="default", header="bearer"):
    token = c.token if token == "default" else token
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization" if header == "bearer" else "X-Ingest-Token"] = f"Bearer {token}" if header == "bearer" else token
    return c.client.post(antiestafa.INGEST_PATH, content=json.dumps(body), headers=headers)


def test_requires_a_valid_token_for_that_organization(api):
    assert post(api, EVENT, token=None).status_code == 401
    assert post(api, EVENT, token="otro").status_code == 401
    from backend.shared.ingest_auth import org_ingest_token
    assert post(api, EVENT, token=org_ingest_token("otra-org")).status_code == 401   # el token de otra org no sirve
    assert post(api, EVENT).status_code == 201
    assert post(api, EVENT, token=api.token, header="x").status_code == 201          # tambien por X-Ingest-Token


def test_bad_json_without_token_does_not_reveal_format(api):
    r = api.client.post(antiestafa.INGEST_PATH, content="no es json")
    assert r.status_code == 401
    ok = api.client.post(antiestafa.INGEST_PATH, content="no es json", headers={"Authorization": "Bearer master-token-master-token"})
    assert ok.status_code == 422


def test_scam_event_creates_alert_and_goes_to_soar(api):
    assert seed(api) == 4
    r = post(api, EVENT)
    assert r.status_code == 201 and r.json()["alerts_created"] == 1 and r.json()["indexed"] == 1
    assert api.soar == [(antiestafa.RULE_NAMES[0], "acme-sa")]
    assert api.indexed[0]["antiestafa"]["veredicto"] == "estafa"


def test_without_rules_the_event_is_indexed_but_no_alert(api):
    r = post(api, EVENT)
    assert r.status_code == 201 and r.json()["alerts_created"] == 0 and r.json()["indexed"] == 1


def test_test_event_does_not_open_alerts_or_cases(api):
    seed(api)
    r = post(api, ev(message="[PRUEBA] conexion de AntiEstafa"))
    assert r.status_code == 201 and r.json()["test"] is True and r.json()["alerts_created"] == 0
    assert api.soar == []
    st = api.client.get("/integrations/antiestafa/status", headers=auth(api))
    assert st.json()["last_received"]["test"] is True


def test_rejects_foreign_event_and_oversized_body(api):
    assert post(api, {"organization": {"id": "acme-sa"}, "event": {"module": "otro"}}).status_code == 422
    big = ev()
    big["message"] = "x" * 70_000
    assert post(api, big).status_code == 413


def test_campaign_after_three_reports_only_once(api):
    seed(api)
    for i in range(2):
        r = post(api, ev(**{"@timestamp": f"2026-10-25T19:0{i}:00Z"}, ae={"huella": f"h{i}"}))
        assert r.json()["campaigns"] == 0
    third = post(api, ev(**{"@timestamp": "2026-10-25T19:05:00Z"}, ae={"huella": "h3"}))   # mismo dominio, tercer reporte
    assert third.json()["campaigns"] == 1 and third.json()["alerts_created"] == 2
    fourth = post(api, ev(**{"@timestamp": "2026-10-25T19:06:00Z"}, ae={"huella": "h4"}))
    assert fourth.json()["campaigns"] == 0   # ya se aviso
    names = [n for n, _ in api.soar]
    assert names.count(antiestafa.RULE_NAMES[3]) == 1


def test_status_summarises_the_week(api):
    from backend.shared.security import create_access_token
    seed(api)
    post(api, ev(ae={"huella": "a"}))
    post(api, ev(outcome="sospechoso", ae={"canal": "link", "dominios": ["otro.example"], "huella": "b"}))
    st = api.client.get("/integrations/antiestafa/status", headers=auth(api)).json()
    assert st["reports"] == 2 and st["by_outcome"] == {"estafa": 1, "sospechoso": 1}
    assert st["rules"]["active"] == 4 and st["rules"]["missing"] == []
    assert {d["domain"] for d in st["top_domains"]} == {"mercadopag0-seguridad.example", "otro.example"}
    other = api.client.get("/integrations/antiestafa/status", headers=auth(api, org="otra")).json()
    assert other["reports"] == 0 and other["rules"]["active"] == 0   # cada organizacion ve lo suyo


def auth(c, org="acme-sa", role="admin"):
    from backend.shared.security import create_access_token
    return {"Authorization": "Bearer " + create_access_token("u@x.com", role, org_id=org)}


def test_setup_is_idempotent_and_needs_a_manager_role(api):
    assert api.client.post("/integrations/antiestafa/setup", headers=auth(api, role="viewer")).status_code == 403
    first = api.client.post("/integrations/antiestafa/setup", headers=auth(api)).json()
    second = api.client.post("/integrations/antiestafa/setup", headers=auth(api)).json()
    assert len(first["created"]) == 4 and second["created"] == []
    assert first["status"]["rules"]["active"] == 4
