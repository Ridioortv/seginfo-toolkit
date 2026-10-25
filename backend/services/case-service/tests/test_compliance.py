"""Cumplimiento con evidencia viva: comprobaciones automaticas, declaraciones, puntajes, cuestionario, API, firma."""
import asyncio
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import compliance_catalog as cat
from app import compliance_evidence as evd
from app import compliance_service as svc
from app import main, services
from app.assets import verificar_evidencia as ver
from app.compliance_models import ComplianceDeclaration
from backend.shared import custody_core as core
from backend.shared.database import get_db
from backend.shared.security import create_access_token
from custody_helpers import file_db

A, B = "org-a", "org-b"
NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


def ok(data):
    return {"ok": True, "data": data}


def down(err="ConnectError"):
    return {"ok": False, "error": err}


def users(*rows):
    return ok([{"id": f"u{i}", "email": f"u{i}@x.com", "full_name": "x", "role_name": r, "is_active": act,
                "mfa_enabled": mfa, "auth_provider": prov} for i, (r, mfa, act, prov) in enumerate(rows)])


def good_facts():
    return {
        "users": users(("admin", True, True, "local"), ("analyst", True, True, "local"), ("viewer", True, True, "local")),
        "sso": ok(None),
        "assets": ok([{"id": "a1", "owner": "ana"}, {"id": "a2", "owner": "luis"}]),
        "scans": ok({"completed_in_window": 4, "schedules_enabled": 2, "schedules_total": 2, "last_completed_at": "2026-10-23T10:00:00+00:00"}),
        "posture": ok({"open_total": 3, "open_by_severity": {"high": 2, "low": 1}, "open_kev": 0, "oldest_open_days": {"critical": 0, "high": 12}}),
        "closure": ok({"counts": {"verified": 5}, "remediated_total": 5, "remediated_unverified": 0}),
        "siem_latest": ok([{"@timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}]),
        "siem_rules": ok([{"id": "r1"}, {"id": "r2"}]),
        "playbooks": ok([{"id": "p1", "is_enabled": True}]),
        "custody": ok({"ok": True, "entries": 30, "reason": ""}),
        "cases": ok({"total": 4, "open": 1, "stale_open": 0}),
        "sovereignty": ok({"verdict": "controlled", "summary": {"external_destinations": 2, "unknown_destinations": 0}}),
    }


def status_of(facts, check):
    return evd.run_check(check, facts)["status"]


# ----------------------------- comprobaciones -----------------------------

def test_everything_good_is_cumple():
    f = good_facts()
    for c in cat.CONTROLS:
        if c["mode"] == "auto":
            assert status_of(f, c["check"]) == "cumple", c["id"]


def test_every_auto_control_has_a_check_and_ids_are_unique():
    ids = [c["id"] for c in cat.CONTROLS]
    assert len(ids) == len(set(ids))
    for c in cat.CONTROLS:
        assert c["area"] in cat.AREAS and c["refs"] and c["why"] and c["title"]
        if c["mode"] == "auto":
            assert c["check"] in evd.CHECKS
    for q in cat.INSURANCE_QUESTIONS:
        assert all(cid in cat.CONTROL_BY_ID for cid in q["controls"])


def test_source_down_is_sin_datos_never_cumple():
    for c in cat.CONTROLS:
        if c["mode"] != "auto":
            continue
        f = {k: down() for k in good_facts()}
        r = evd.run_check(c["check"], f)
        assert r["status"] == "sin_datos", c["id"]
        assert "-service" in r["summary"]["args"][0] and "ConnectError" in r["summary"]["args"][0]
    # una sola fuente caida solo afecta a los controles que la usan
    f = good_facts()
    f["users"] = down("ReadTimeout")
    assert status_of(f, "mfa_admins") == "sin_datos" and status_of(f, "assets_inventory") == "cumple"


def test_mfa_admins_states():
    assert status_of({"users": users(("admin", False, True, "local"), ("admin", False, True, "local"))}, "mfa_admins") == "no_cumple"
    assert status_of({"users": users(("admin", True, True, "local"), ("admin", False, True, "local"))}, "mfa_admins") == "parcial"
    # inactivos no cuentan; SSO no se puede comprobar
    assert status_of({"users": users(("admin", False, False, "local"), ("admin", True, True, "local"))}, "mfa_admins") == "cumple"
    r = evd.run_check("mfa_admins", {"users": users(("admin", False, True, "google"))})
    assert r["status"] == "sin_datos" and "SSO" in r["summary"]["text"]
    assert status_of({"users": users()}, "mfa_admins") == "sin_datos"


def test_mfa_all_thresholds():
    rows = [("analyst", True, True, "local")] * 2 + [("analyst", False, True, "local")]
    assert status_of({"users": users(*rows)}, "mfa_all") == "parcial"
    rows = [("analyst", True, True, "local")] + [("analyst", False, True, "local")] * 3
    r = evd.run_check("mfa_all", {"users": users(*rows)})
    assert r["status"] == "no_cumple" and r["summary"]["args"] == ["1", "4", "25"]


def test_admin_share():
    many = [("admin", True, True, "local")] * 5 + [("viewer", True, True, "local")] * 2
    assert status_of({"users": users(*many)}, "admin_share") == "no_cumple"
    big_org = [("admin", True, True, "local")] * 5 + [("viewer", True, True, "local")] * 15
    assert status_of({"users": users(*big_org)}, "admin_share") == "cumple"


def test_assets_inventory():
    assert status_of({"assets": ok([])}, "assets_inventory") == "no_cumple"
    assert status_of({"assets": ok([{"owner": ""}, {"owner": "x"}])}, "assets_inventory") == "parcial"


def test_scans_recent_combinations():
    def f(recent, sched):
        return {"scans": ok({"completed_in_window": recent, "schedules_enabled": sched, "last_completed_at": None})}
    assert status_of(f(2, 1), "scans_recent") == "cumple"
    assert status_of(f(2, 0), "scans_recent") == "parcial"
    assert status_of(f(0, 1), "scans_recent") == "parcial"
    assert status_of(f(0, 0), "scans_recent") == "no_cumple"


def test_open_critical_and_kev():
    def f(sev, kev=0, oldest=0):
        return {"posture": ok({"open_by_severity": sev, "open_kev": kev, "oldest_open_days": {"critical": oldest}})}
    assert status_of(f({"high": 9}), "vulns_open_critical") == "cumple"
    assert status_of(f({"critical": 1}, oldest=10), "vulns_open_critical") == "parcial"
    assert status_of(f({"critical": 1}, oldest=45), "vulns_open_critical") == "no_cumple"
    assert status_of(f({}, kev=1), "vulns_open_critical") == "no_cumple"


def test_closure_verified_states():
    def f(counts, total, unverified):
        return {"closure": ok({"counts": counts, "remediated_total": total, "remediated_unverified": unverified})}
    assert status_of(f({}, 0, 0), "closure_verified") == "sin_datos"
    assert status_of(f({"verified": 3}, 3, 0), "closure_verified") == "cumple"
    assert status_of(f({"verified": 3}, 5, 2), "closure_verified") == "parcial"
    assert status_of(f({}, 4, 4), "closure_verified") == "no_cumple"


def test_siem_freshness():
    old = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    assert status_of({"siem_latest": ok([{"@timestamp": old}])}, "siem_recent") == "parcial"
    assert status_of({"siem_latest": ok([])}, "siem_recent") == "no_cumple"
    assert status_of({"siem_rules": ok([])}, "siem_rules") == "no_cumple"


def test_custody_sovereignty_cases_playbooks():
    assert status_of({"custody": ok({"ok": False, "entries": 9, "reason": "x"})}, "custody_chain") == "no_cumple"
    assert status_of({"custody": ok({"ok": True, "entries": 0})}, "custody_chain") == "sin_datos"
    sv = lambda v: {"sovereignty": ok({"verdict": v, "summary": {}})}
    assert status_of(sv("isolated_verified"), "sovereignty") == "cumple"
    assert status_of(sv("isolated_unverified"), "sovereignty") == "parcial"
    assert status_of(sv("unexpected"), "sovereignty") == "no_cumple"
    assert status_of(sv("no_data"), "sovereignty") == "sin_datos"
    assert status_of({"cases": ok({"total": 3, "open": 2, "stale_open": 1})}, "cases_handling") == "parcial"
    assert status_of({"cases": ok({"total": 0, "open": 0, "stale_open": 0})}, "cases_handling") == "sin_datos"
    assert status_of({"playbooks": ok([{"is_enabled": False}])}, "soar_playbooks") == "no_cumple"


def test_a_broken_check_never_reports_cumple():
    r = evd.run_check("mfa_admins", {"users": ok("no es una lista")})
    assert r["status"] == "sin_datos"


# ----------------------------- evaluacion y puntajes -----------------------------

def decl(control, answer="yes", note="Lo tenemos documentado en la carpeta de politicas", until=None, by="ana@acme.com"):
    return ComplianceDeclaration(organization_id=A, control_id=control, answer=answer, note=note, declared_by=by,
                                 declared_at=NOW, valid_until=until or NOW + timedelta(days=100))


def test_manual_controls_start_pending_and_declarations_count_as_declared():
    items = svc.evaluate_controls(good_facts(), {}, NOW)
    by = {i["id"]: i for i in items}
    assert by["RES-01"]["status"] == "pendiente" and by["RES-01"]["basis"] == "ninguno"
    items = svc.evaluate_controls(good_facts(), {"RES-01": decl("RES-01"), "TEC-01": decl("TEC-01", "partial"), "PER-01": decl("PER-01", "no")}, NOW)
    by = {i["id"]: i for i in items}
    assert (by["RES-01"]["status"], by["RES-01"]["basis"]) == ("declarado_si", "declarado")
    assert by["TEC-01"]["status"] == "declarado_parcial" and by["PER-01"]["status"] == "declarado_no"


def test_expired_declaration_does_not_count():
    old = decl("RES-01", until=NOW - timedelta(days=1))
    by = {i["id"]: i for i in svc.evaluate_controls(good_facts(), {"RES-01": old}, NOW)}
    assert by["RES-01"]["status"] == "vencido" and by["RES-01"]["declaration"]["expired"] is True


def test_declaration_fills_in_an_auto_control_only_when_there_is_no_data():
    f = good_facts()
    f["users"] = users(("admin", False, True, "google"))
    by = {i["id"]: i for i in svc.evaluate_controls(f, {"ACC-01": decl("ACC-01")}, NOW)}
    assert by["ACC-01"]["status"] == "declarado_si" and by["ACC-01"]["basis"] == "declarado"
    # con datos reales, la declaracion NO pisa lo que TERO ve
    f2 = good_facts()
    f2["users"] = users(("admin", False, True, "local"))
    by = {i["id"]: i for i in svc.evaluate_controls(f2, {"ACC-01": decl("ACC-01")}, NOW)}
    assert by["ACC-01"]["status"] == "no_cumple" and by["ACC-01"]["basis"] == "verificado"


def test_scores_keep_verified_and_declared_apart():
    items = svc.evaluate_controls(good_facts(), {}, NOW)
    s = svc.scores(items)
    assert s["score_verified"] == 100.0 and s["verified_controls"] == s["automatic_controls"] == 13
    assert s["total_controls"] == len(cat.CONTROLS)
    # lo pendiente baja el total pero no lo verificado
    assert s["score_total"] == round(100 * 13 / len(cat.CONTROLS), 1)
    decls = {c["id"]: decl(c["id"]) for c in cat.CONTROLS if c["mode"] == "manual"}
    s2 = svc.scores(svc.evaluate_controls(good_facts(), decls, NOW))
    assert s2["score_total"] == 100.0 and s2["score_verified"] == 100.0
    # declarar 'no' en todo no cambia lo verificado
    decls = {c["id"]: decl(c["id"], "no") for c in cat.CONTROLS if c["mode"] == "manual"}
    s3 = svc.scores(svc.evaluate_controls(good_facts(), decls, NOW))
    assert s3["score_verified"] == 100.0 and s3["score_total"] < 50


def test_no_data_at_all_gives_no_verified_score():
    facts = {k: down() for k in good_facts()}
    s = svc.scores(svc.evaluate_controls(facts, {}, NOW))
    assert s["score_verified"] is None and s["verified_controls"] == 0 and s["score_total"] == 0.0


def test_questionnaire_answers():
    f = good_facts()
    items = svc.evaluate_controls(f, {}, NOW)
    q = {x["id"]: x for x in svc.questionnaire(items)}
    assert q["Q01"]["answer"] == "yes" and q["Q04"]["answer"] == "yes"
    assert q["Q11"]["answer"] == "pending"  # respaldo: nadie lo declaro
    assert q["Q09"]["answer"] == "pending"  # plan escrito pendiente + playbooks ok
    f["users"] = users(("admin", False, True, "local"))
    q = {x["id"]: x for x in svc.questionnaire(svc.evaluate_controls(f, {}, NOW))}
    assert q["Q01"]["answer"] == "no"
    f["closure"] = ok({"counts": {}, "remediated_total": 3, "remediated_unverified": 3})
    q = {x["id"]: x for x in svc.questionnaire(svc.evaluate_controls(f, {}, NOW))}
    assert q["Q06"]["answer"] == "partial"  # VUL-02 cumple, VUL-03 no cumple
    assert all(c["basis"] in ("verificado", "declarado", "ninguno") for x in q.values() for c in x["controls"])


# ----------------------------- API -----------------------------

def tok(role="admin", org=A, email="ana@acme.com"):
    return {"Authorization": "Bearer " + create_access_token("u1", role, org_id=org, email=email)}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")
    engine, Session = file_db()

    async def override():
        async with Session() as session:
            yield session

    async def fake_gather(db, org_id, client=None):
        facts = good_facts()
        facts["custody"] = ok({"ok": True, "entries": 5, "reason": ""})
        facts["sovereignty"] = ok({"verdict": "controlled", "summary": {}})
        facts["cases"] = ok({"total": 1, "open": 0, "stale_open": 0})
        return facts

    monkeypatch.setattr(evd, "gather", fake_gather)
    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def test_roles(client):
    assert client.get("/compliance/status").status_code == 401
    assert client.get("/compliance/status", headers=tok("viewer")).status_code == 403
    assert client.get("/compliance/status", headers=tok("analyst")).status_code == 200
    body = {"control_id": "RES-01", "answer": "yes", "note": "Restauramos el 3/10, consta en el acta"}
    assert client.post("/compliance/declarations", json=body, headers=tok("analyst")).status_code == 403
    assert client.post("/compliance/snapshot", headers=tok("analyst")).status_code == 403
    assert client.get("/compliance/attestation", headers=tok("analyst")).status_code == 403
    assert client.post("/compliance/declarations", json=body, headers=tok("soc_manager")).status_code == 201


def test_status_shape(client):
    r = client.get("/compliance/status", headers=tok()).json()
    assert len(r["controls"]) == len(cat.CONTROLS) and len(r["questionnaire"]) == 18
    assert r["summary"]["score_verified"] == 100.0 and r["disclaimer"] and r["history"] == []
    first = r["controls"][0]
    assert {"id", "title", "status", "basis", "summary", "evidence", "refs", "mode", "why", "area_label"} <= set(first)
    assert isinstance(first["summary"]["args"], list)


def test_declare_validation_and_flow(client):
    bad = {"control_id": "NOPE-01", "answer": "yes", "note": "una nota suficientemente larga"}
    assert client.post("/compliance/declarations", json=bad, headers=tok()).status_code == 422
    short = {"control_id": "RES-01", "answer": "yes", "note": "si"}
    assert client.post("/compliance/declarations", json=short, headers=tok()).status_code == 422
    wrong = {"control_id": "RES-01", "answer": "maybe", "note": "una nota suficientemente larga"}
    assert client.post("/compliance/declarations", json=wrong, headers=tok()).status_code == 422
    ok_body = {"control_id": "RES-01", "answer": "yes", "note": "Restauramos el 3/10, consta en el acta", "valid_months": 6}
    assert client.post("/compliance/declarations", json=ok_body, headers=tok()).status_code == 201
    st = client.get("/compliance/status", headers=tok()).json()
    res = next(c for c in st["controls"] if c["id"] == "RES-01")
    assert res["status"] == "declarado_si" and res["declaration"]["declared_by"] == "ana@acme.com"
    # actualizar reemplaza, no duplica
    ok_body["answer"] = "partial"
    assert client.post("/compliance/declarations", json=ok_body, headers=tok()).status_code == 201
    res = next(c for c in client.get("/compliance/status", headers=tok()).json()["controls"] if c["id"] == "RES-01")
    assert res["status"] == "declarado_parcial"
    assert client.delete("/compliance/declarations/RES-01", headers=tok()).status_code == 204
    assert client.delete("/compliance/declarations/RES-01", headers=tok()).status_code == 404
    res = next(c for c in client.get("/compliance/status", headers=tok()).json()["controls"] if c["id"] == "RES-01")
    assert res["status"] == "pendiente"


def test_declarations_are_per_organization(client):
    body = {"control_id": "RES-01", "answer": "yes", "note": "Restauramos el 3/10, consta en el acta"}
    assert client.post("/compliance/declarations", json=body, headers=tok(org=A)).status_code == 201
    other = next(c for c in client.get("/compliance/status", headers=tok(org=B)).json()["controls"] if c["id"] == "RES-01")
    assert other["status"] == "pendiente"
    assert client.delete("/compliance/declarations/RES-01", headers=tok(org=B)).status_code == 404


def custody_types(client, org=A):
    r = client.get("/custody/entries", headers=tok(org=org), params={"limit": 200}).json()
    items = r["items"]
    return [e["event_type"] for e in items]


def test_declarations_snapshots_and_attestations_go_to_the_chain(client):
    body = {"control_id": "RES-01", "answer": "yes", "note": "Restauramos el 3/10, consta en el acta"}
    client.post("/compliance/declarations", json=body, headers=tok())
    assert client.post("/compliance/snapshot", headers=tok()).status_code == 201
    assert client.get("/compliance/attestation", headers=tok()).status_code == 200
    client.delete("/compliance/declarations/RES-01", headers=tok())
    types = custody_types(client)
    for t in ("compliance.declaration", "compliance.snapshot", "compliance.attestation", "compliance.declaration_removed"):
        assert t in types, types
    v = client.get("/custody/verify", headers=tok()).json()
    assert v["ok"] is True


def test_snapshot_history(client):
    snap = client.post("/compliance/snapshot", headers=tok()).json()
    assert snap["score_verified"] == 100.0 and len(snap["body_sha256"]) == 64
    client.post("/compliance/snapshot", headers=tok())
    hist = client.get("/compliance/status", headers=tok()).json()["history"]
    assert len(hist) == 2 and hist[0]["created_at"] <= hist[1]["created_at"]
    assert client.get("/compliance/status", headers=tok(org=B)).json()["history"] == []


def test_attestation_is_signed_verifiable_and_tamper_evident(client, tmp_path):
    body = {"control_id": "RES-01", "answer": "yes", "note": "Restauramos el 3/10, consta en el acta"}
    client.post("/compliance/declarations", json=body, headers=tok())
    r = client.get("/compliance/attestation", headers=tok())
    doc = r.json()
    assert doc["kind"] == "compliance" and doc["body"]["total_controls"] == len(cat.CONTROLS)
    assert "25.326" in doc["body"]["legal_references"]["ley"] and "47/2018" in doc["body"]["legal_references"]["recomendaciones"]
    assert core.verify_attestation(doc)["ok"] is True and ver.verify_attestation(doc)["ok"] is True
    path = tmp_path / "a.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    run = subprocess.run([sys.executable, str(ver.__file__), str(path)], capture_output=True, text=True)
    assert run.returncode == 0 and "ATESTADO INTEGRO" in run.stdout
    res = next(c for c in doc["body"]["controls"] if c["id"] == "RES-01")
    assert res["basis"] == "declarado" and res["declaration"]["declared_by"] == "ana@acme.com"
    doc["body"]["score_verified"] = 100.0
    doc["body"]["controls"][0]["status"] = "no_cumple" if doc["body"]["controls"][0]["status"] != "no_cumple" else "cumple"
    path.write_text(json.dumps(doc), encoding="utf-8")
    run = subprocess.run([sys.executable, str(ver.__file__), str(path)], capture_output=True, text=True)
    assert run.returncode != 0 and "NO CONFIABLE" in run.stdout


def test_questionnaire_csv(client):
    client.post("/compliance/declarations", headers=tok(), json={
        "control_id": "RES-01", "answer": "yes", "note": "=cmd|' /C calc'!A0 es una nota con formula"})
    r = client.get("/compliance/questionnaire.csv", headers=tok("analyst"))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'filename="cuestionario-ciberseguro.csv"' in r.headers["content-disposition"]
    text = r.content.decode("utf-8")
    assert text.startswith("﻿") and text.count("\nQ") + text.startswith("﻿Id") >= 18
    lines = [l for l in text.splitlines() if l.startswith("Q")]
    assert len(lines) == 18
    assert "Si" in text and "No es asesoramiento legal" in text
    # nada que empiece con = + - @ al inicio de una celda (inyeccion de formulas)
    import csv, io
    for row in csv.reader(io.StringIO(text.lstrip("﻿"))):
        for cell in row:
            assert cell[:1] not in ("=", "+", "@"), cell


def test_text_templates_are_complete():
    # Cada resumen es una plantilla con sus valores: el CSV y el atestado la completan sin dejar llaves sueltas.
    items = svc.evaluate_controls(good_facts(), {}, NOW)
    for i in items:
        text = svc.render(i["summary"])
        assert "{" not in text and "}" not in text, (i["id"], text)


# ----------------------------- recoleccion real (HTTP simulado) -----------------------------

def test_gather_calls_each_service_with_an_org_token_and_survives_failures():
    import httpx
    from backend.shared.security import decode_token
    from custody_helpers import run_db

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        claims = decode_token(request.headers["authorization"].split()[1])
        seen.append((request.url.host, request.url.path, claims.get("org_id"), claims.get("sub"), claims.get("role")))
        path = request.url.path
        if path.endswith("/users"):
            return httpx.Response(200, json=[])
        if path == "/scans/summary":
            return httpx.Response(500)
        if path == "/logs/search":
            raise httpx.ConnectError("sin red")
        return httpx.Response(200, json={} if "summary" not in path else {})

    async def body(factory):
        async with factory() as db:
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            return await evd.gather(db, A, client)

    facts = run_db(body)
    assert facts["users"] == {"ok": True, "data": []}
    assert facts["scans"] == {"ok": False, "error": "HTTP 500"}
    assert facts["siem_latest"] == {"ok": False, "error": "ConnectError"}
    assert facts["custody"]["ok"] and facts["cases"]["data"]["total"] == 0 and "verdict" in facts["sovereignty"]["data"]
    hosts = {h for h, *_ in seen}
    assert hosts == {"auth-service", "asset-service", "scan-service", "vuln-service", "siem-service", "soar-service"}
    assert all(org == A and sub == "system:case-service" and role == "admin" for _, _, org, sub, role in seen)
    paths = {p for _, p, *_ in seen}
    assert f"/auth/organizations/{A}/users" in paths and "/vulnerabilities/posture" in paths and "/scans/summary" in paths
