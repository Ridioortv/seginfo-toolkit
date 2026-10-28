"""Tablero ejecutivo: comparacion con el periodo anterior, exposicion por unidad de negocio, reglas de atencion,
informe firmado que se verifica offline y roles."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import compliance_service
from app import executive_service as svc
from app import main
from app.assets import verificar_evidencia as ver
from backend.shared.database import get_db
from backend.shared.security import create_access_token
from custody_helpers import file_db

A, B = "org-a", "org-b"
NOW = datetime(2026, 6, 30, 12, tzinfo=timezone.utc)


def tok(role="admin", org=A, email="dir@acme.com"):
    return {"Authorization": "Bearer " + create_access_token(email, role, org_id=org, email=email)}


# ------------------------------ unidades puras ------------------------------

def test_delta_handles_missing_and_zero_base():
    assert svc.delta(10, 8) == {"current": 10, "previous": 8, "change": 2, "change_pct": 25.0}
    assert svc.delta(3, 0)["change_pct"] is None and svc.delta(3, 0)["change"] == 3
    assert svc.delta(None, 4)["change"] is None and svc.delta(4, None)["change_pct"] is None


def test_clamp_days():
    assert svc.clamp_days(1) == 7 and svc.clamp_days(9999) == 365 and svc.clamp_days("x") == 30 and svc.clamp_days(None) == 30


def test_cases_metrics_period_windows_and_sla():
    d = lambda n: NOW - timedelta(days=n)
    rows = [
        ("open", d(2), None, d(1)),                     # abierto y vencido
        ("in_progress", d(1), None, NOW + timedelta(hours=4)),
        ("resolved", d(10), d(8), d(7)),                # cerrado a tiempo en el periodo (48 h)
        ("closed", d(12), d(5), d(11)),                 # cerrado tarde en el periodo (168 h)
        ("resolved", d(50), d(40), d(49)),              # periodo anterior
    ]
    k = svc.cases_metrics(rows, NOW, 30)
    assert k["open"] == 2 and k["overdue"] == 1 and k["total"] == 5
    assert k["opened"]["current"] == 4 and k["opened"]["previous"] == 1
    assert k["resolved"]["current"] == 2 and k["resolved"]["previous"] == 1
    assert k["mttr_hours"]["current"] == 108.0 and k["mttr_hours"]["previous"] == 240.0
    assert k["sla_met_pct"] == 50.0 and k["sla_measured"] == 2


def test_exposure_groups_by_unit_and_lists_unassigned_apart():
    assets = [{"id": "a1", "hostname": "erp", "business_unit": "Finanzas", "criticality": "critical"},
              {"id": "a2", "hostname": "web", "business_unit": "Comercial", "criticality": "high"},
              {"id": "a3", "hostname": "pc", "business_unit": "", "criticality": "low"},
              {"id": "a4", "hostname": "quieto", "business_unit": "RRHH", "criticality": "low"}]
    by_asset = [{"asset_id": "a1", "critical": 1, "high": 0, "medium": 0, "low": 0, "kev": 1, "score": 15.0},
                {"asset_id": "a2", "critical": 0, "high": 2, "medium": 0, "low": 0, "kev": 0, "score": 10.0},
                {"asset_id": "a3", "critical": 0, "high": 0, "medium": 1, "low": 0, "kev": 0, "score": 2.0},
                {"asset_id": "gone", "critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0, "score": 5.0}]
    x = svc.exposure_by_unit(by_asset, assets)
    units = {u["unit"]: u for u in x["by_business_unit"]}
    assert x["by_business_unit"][0]["unit"] == "Finanzas" and units["Finanzas"]["share_pct"] == 46.9
    assert units["RRHH"]["assets"] == 1 and units["RRHH"]["score"] == 0
    # el activo sin unidad y el activo que ya no existe caen juntos en "sin unidad"
    assert units[svc.UNASSIGNED]["score"] == 7.0 and units[svc.UNASSIGNED]["assets"] == 1
    assert x["total_score"] == 32.0 and x["units_defined"] == 3
    assert next(t for t in x["top_assets"] if t["asset_id"] == "gone")["known"] is False


def facts_ok(**over):
    ex = {"days": 30, "open": {"total": 5, "by_severity": {"critical": 1, "high": 2, "medium": 2}, "kev": 1, "critical_high": 3,
                               "oldest_critical_high_days": 95, "accepted_risk": 1},
          "period": {"created": 6, "remediated": 2, "created_critical_high": 4, "remediated_critical_high": 1},
          "previous": {"created": 3, "remediated": 3, "created_critical_high": 1, "remediated_critical_high": 2},
          "exposure_weights": {"critical": 10}, "by_asset": []}
    closure = {"counts": {"verified": 3, "failed": 1}, "remediated_total": 5, "remediated_unverified": 1,
               "mttr_declared_hours": 24, "mttr_real_hours": 120, "false_closure_rate_pct": 25.0, "by_severity": {}}
    f = {"executive": {"ok": True, "data": ex}, "closure": {"ok": True, "data": closure}, "assets": {"ok": True, "data": []},
         "drills": {"ok": True, "data": {"completed_total": 0}},
         "cases": svc.cases_metrics([], NOW, 30), "exceptions": {"pending": 0, "active": 0, "active_critical_or_high": 0, "expiring_soon": 0},
         "vendors": {"high_or_critical_risk": 0, "without_assessment_critical_or_high": 0},
         "custody": {"ok": True, "entries": 4, "head_hash": "h"},
         "compliance": {"summary": {"score_verified": 40.0, "score_total": 50.0, "verified_controls": 5, "total_controls": 12, "counts": {}}},
         "compliance_history": [{"created_at": (NOW - timedelta(days=40)).isoformat(), "score_verified": 52.0}],
         "sources": {"vuln-service": {"ok": True}}}
    f.update(over)
    return f


def test_build_summary_compares_periods_and_flags_what_needs_attention():
    s = svc.build_summary(facts_ok(), NOW, 30)
    v = s["vulnerabilities"]
    assert v["created_critical_high"]["current"] == 4 and v["created_critical_high"]["previous"] == 1
    assert s["remediation"]["gap_hours"] == 96 and s["compliance"]["previous_score_verified"] == 52.0 and s["compliance"]["change"] == -12.0
    codes = {a["code"]: a["level"] for a in s["attention"]}
    assert codes["kev_open"] == "critical" and codes["oldest_90"] == "critical" and s["status"] == "attention"
    assert {"ch_flow", "false_closure", "mttr_gap", "compliance_drop", "compliance_low", "no_drill"} <= set(codes)
    # criticas primero
    levels = [a["level"] for a in s["attention"]]
    assert levels == sorted(levels, key=["critical", "warning", "info"].index)


def test_stable_when_nothing_to_flag_and_missing_source_is_reported_not_zeroed():
    f = facts_ok()
    f["executive"]["data"]["open"].update(kev=0, oldest_critical_high_days=3, critical_high=0, by_severity={})
    f["executive"]["data"]["period"].update(created_critical_high=0, remediated_critical_high=0)
    f["closure"]["data"].update(false_closure_rate_pct=0, mttr_real_hours=20, remediated_unverified=0)
    f["compliance"]["summary"]["score_verified"] = 80.0
    f["drills"]["data"] = {"completed_total": 2, "days_since_last": 30}
    s = svc.build_summary(f, NOW, 30)
    assert s["status"] == "stable" and s["attention"] == []
    down = facts_ok(executive={"ok": False, "error": "HTTP 502"}, sources={"vuln-service": {"ok": False, "error": "HTTP 502"}})
    s2 = svc.build_summary(down, NOW, 30)
    assert "vulnerabilities" not in s2 and "exposure" not in s2
    assert any(a["code"] == "source_down" for a in s2["attention"])


def test_broken_custody_is_critical():
    s = svc.build_summary(facts_ok(custody={"ok": False, "entries": 9, "head_hash": "x"}), NOW, 30)
    assert any(a["code"] == "custody_broken" and a["level"] == "critical" for a in s["attention"])


# ------------------------------ API ------------------------------

@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")
    ex = {"days": 30, "generated_at": NOW.isoformat(),
          "open": {"total": 2, "by_severity": {"critical": 1, "high": 1}, "kev": 0, "critical_high": 2, "oldest_critical_high_days": 10, "accepted_risk": 0},
          "period": {"created": 2, "remediated": 1, "created_critical_high": 2, "remediated_critical_high": 1},
          "previous": {"created": 1, "remediated": 0, "created_critical_high": 0, "remediated_critical_high": 0},
          "exposure_weights": {"critical": 10, "high": 5, "medium": 2, "low": 0.5},
          "by_asset": [{"asset_id": "a1", "critical": 1, "high": 0, "medium": 0, "low": 0, "kev": 0, "score": 10.0},
                       {"asset_id": "a2", "critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0, "score": 5.0}]}
    closure = {"counts": {"verified": 1, "failed": 0}, "remediated_total": 1, "remediated_unverified": 0,
               "mttr_declared_hours": 10, "mttr_real_hours": 12, "false_closure_rate_pct": 0.0, "by_severity": {}}
    assets = [{"id": "a1", "hostname": "erp", "business_unit": "Finanzas", "criticality": "critical"},
              {"id": "a2", "hostname": "web", "business_unit": "", "criticality": "high"}]
    calls = []

    async def fake_get(client, org_id, key, path, params=None):
        calls.append((org_id, key, path))
        if key == "vuln" and path.endswith("/executive"):
            return {"ok": True, "data": ex}
        if key == "vuln":
            return {"ok": True, "data": closure}
        if key == "asset":
            return {"ok": True, "data": assets}
        if key == "purple":
            return {"ok": True, "data": {"completed_total": 1, "days_since_last": 20, "last_score": 85}}
        return {"ok": False, "error": "no mock"}  # el resto de las fuentes del cumplimiento queda "sin datos"

    async def fake_name(org):
        return "Acme SA"

    from app import compliance_evidence
    monkeypatch.setattr(svc, "_get", fake_get)
    monkeypatch.setattr(compliance_evidence, "_get", fake_get)
    monkeypatch.setattr(svc, "org_name", fake_name)
    engine, Session = file_db()

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app), calls
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def test_roles(env):
    client, _ = env
    assert client.get("/executive/summary").status_code == 401
    assert client.get("/executive/summary", headers=tok("viewer")).status_code == 200      # la direccion puede ser solo lectura
    assert client.post("/executive/report", headers=tok("viewer")).status_code == 403
    assert client.post("/executive/report", headers=tok("analyst")).status_code == 403
    assert client.get("/executive/summary?days=3", headers=tok()).status_code == 422


def test_summary_joins_vulnerabilities_with_business_units_and_is_tenant_scoped(env):
    client, calls = env
    s = client.get("/executive/summary?days=30", headers=tok(org=B)).json()
    assert s["organization"] == {"id": B, "name": "Acme SA"} and s["days"] == 30
    units = {u["unit"]: u for u in s["exposure"]["by_business_unit"]}
    assert units["Finanzas"]["score"] == 10.0 and units[svc.UNASSIGNED]["score"] == 5.0
    assert s["vulnerabilities"]["critical_high"] == 2 and s["remediation"]["gap_hours"] == 2
    assert s["drills"]["last_score"] == 85 and s["custody"]["ok"] is True
    assert all(org == B for org, *_ in calls)           # cada llamada sale con el token de SU organizacion


def test_signed_report_verifies_offline_and_breaks_when_tampered(env, tmp_path):
    client, _ = env
    r = client.post("/executive/report?days=30", headers=tok())
    assert r.status_code == 200 and "informe-ejecutivo" in r.headers["content-disposition"]
    doc = r.json()
    assert doc["kind"] == "executive" and doc["body"]["exposure"]["by_business_unit"][0]["unit"] == "Finanzas"
    assert ver.verify_attestation(doc)["ok"] is True
    doc["body"]["vulnerabilities"]["critical_high"] = 0
    assert ver.verify_attestation(doc)["ok"] is False
    # el hecho queda en la cadena de custodia y la foto del dia alimenta la tendencia
    entries = client.get("/custody/entries?limit=50", headers=tok()).json()["items"]
    assert any(e["event_type"] == "executive.report_signed" for e in entries)
    t = client.get("/executive/trend?days=30", headers=tok()).json()["items"]
    assert len(t) == 1 and t[0]["critical_high"] == 2 and t[0]["open_total"] == 2
    again = client.post("/executive/report?days=30", headers=tok())
    assert again.status_code == 200
    assert len(client.get("/executive/trend?days=30", headers=tok()).json()["items"]) == 1   # una foto por dia
    assert client.get("/executive/trend?days=30", headers=tok(org=B)).json()["items"] == []  # y no se mezcla entre organizaciones
