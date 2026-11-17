"""Riesgo de proveedores: puntaje, cuestionario por link publico, evidencia, aislamiento entre organizaciones y atestado."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import main
from app import vendor_catalog as cat
from app.assets import verificar_evidencia as ver
from backend.shared import custody_core as core
from backend.shared.database import get_db
from backend.shared.security import create_access_token
from custody_helpers import file_db

A, B = "org-a", "org-b"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def tok(role="admin", org=A):
    return {"Authorization": "Bearer " + create_access_token("u1", role, org_id=org, email="ana@acme.com")}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")
    engine, Session = file_db()

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def answers(value="yes", **over):
    out = {q["id"]: {"answer": value} for q in cat.QUESTIONS}
    for k, v in over.items():
        out[k.replace("_", "-")] = {"answer": v}
    return out


def mk_vendor(client, headers=None, **kw):
    body = {"name": "Nube SA", "domain": "nube.com", "criticality": "high", "data_types": ["personal"], **kw}
    r = client.post("/vendors", headers=headers or tok(), json=body)
    assert r.status_code == 201, r.text
    return r.json()


def send_and_answer(client, vendor_id, ans, headers=None):
    r = client.post(f"/vendors/{vendor_id}/assessments", headers=headers or tok(), json={})
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    r2 = client.post(f"/public/vendor-assessments/{token}", json={
        "respondent_name": "Pedro Gomez", "respondent_email": "pedro@nube.com", "answers": ans})
    return token, r2


# ---------------------------------------------------------------- puntaje (funciones puras)

def test_catalog_is_consistent():
    ids = [q["id"] for q in cat.QUESTIONS]
    assert len(ids) == len(set(ids)) == 24
    assert any(q["knockout"] for q in cat.QUESTIONS)
    assert all(set(q) == {"id", "domain", "text"} for q in cat.public_questions())  # el proveedor no ve pesos


def test_all_yes_is_100_and_all_no_is_0_with_knockouts():
    assert cat.control_score(answers("yes"))["base"] == 100.0
    s = cat.control_score(answers("no"))
    assert s["base"] == 0.0 and s["knockout_penalty"] == cat.KNOCKOUT_CAP and len(s["knockouts"]) >= 3


def test_na_is_excluded_not_counted_as_no():
    a = answers("yes", gov_1="na", gov_2="na")
    assert cat.control_score(a)["base"] == 100.0


def test_partial_counts_half():
    a = answers("partial")
    assert cat.control_score(a)["base"] == 50.0


def test_validate_answers_rejects_missing_unknown_and_bad_values():
    a = answers("yes")
    del a["gov-1"]
    with pytest.raises(cat.AnswerError, match="Faltan"):
        cat.validate_answers(a)
    with pytest.raises(cat.AnswerError, match="no existen"):
        cat.validate_answers({**answers("yes"), "zzz": {"answer": "yes"}})
    bad = answers("yes")
    bad["gov-1"] = {"answer": "quizas"}
    with pytest.raises(cat.AnswerError):
        cat.validate_answers(bad)
    with pytest.raises(cat.AnswerError):
        cat.validate_answers("texto")
    ok = cat.validate_answers({**answers("yes"), "gov-1": "no"})  # acepta la forma corta
    assert ok["gov-1"]["answer"] == "no"


def test_risk_level_thresholds_and_criticality_weight():
    def risk(crit, base, pen=0.0, ev=()):
        return cat.assess(crit, {"score_detail": {"base": base, "knockout_penalty": pen}, "completed_at": NOW}, list(ev), NOW)
    assert risk("critical", 100)["level"] == "low"
    assert risk("critical", 30)["level"] == "critical"           # 1.0 x 70 = 70
    assert risk("critical", 30)["index"] > risk("low", 30)["index"]


def test_low_criticality_vendor_with_same_score_is_less_risky():
    d = {"score_detail": {"base": 30.0, "knockout_penalty": 0.0}, "completed_at": NOW}
    assert cat.assess("low", d, [], NOW)["level"] == "medium"
    assert cat.assess("critical", d, [], NOW)["level"] == "critical"


def test_basic_control_failure_never_leaves_risk_low():
    d = {"score_detail": {"base": 96.0, "knockout_penalty": 10.0, "knockouts": ["acc-1"]}, "completed_at": NOW}
    # puntaje efectivo 86 -> indice 14 (bajo) para un proveedor critico, pero hay un control basico en "no"
    assert cat.assess("critical", d, [], NOW)["level"] == "medium"
    clean = {"score_detail": {"base": 86.0, "knockout_penalty": 0.0, "knockouts": []}, "completed_at": NOW}
    assert cat.assess("critical", clean, [], NOW)["level"] == "low"


def test_critical_vendor_with_mfa_and_breach_notice_missing_is_high_risk():
    a = answers("yes", acc_1="no", inc_2="no", bcp_1="partial")
    detail = cat.control_score(a)
    r = cat.assess("critical", {"score_detail": detail, "completed_at": NOW}, [], NOW)
    assert r["level"] in ("high", "critical")


def test_unassessed_is_never_low():
    r = cat.assess("critical", None, [], NOW)
    assert r["level"] == "unassessed" and r["index"] is None


def test_assessment_older_than_a_year_is_stale():
    d = {"score_detail": {"base": 100.0, "knockout_penalty": 0.0}, "completed_at": NOW - timedelta(days=400)}
    r = cat.assess("high", d, [], NOW)
    assert r["level"] == "stale" and r["stale"] is True


def test_expired_evidence_does_not_add_points_and_duplicates_count_once():
    ev = [{"kind": "iso27001", "status": "vigente"}, {"kind": "iso27001", "status": "vigente"},
          {"kind": "soc2", "status": "vencida"}, {"kind": "pentest", "status": "por_vencer"}]
    assert cat.evidence_bonus(ev) == 8.0  # 5 + 3, el SOC 2 vencido no suma
    many = [{"kind": k, "status": "vigente"} for k in ("iso27001", "soc2", "pentest", "dpa")]
    assert cat.evidence_bonus(many) == cat.EVIDENCE_CAP


def test_evidence_status_windows():
    assert cat.evidence_status(NOW - timedelta(days=1), NOW) == "vencida"
    assert cat.evidence_status(NOW + timedelta(days=30), NOW) == "por_vencer"
    assert cat.evidence_status(NOW + timedelta(days=200), NOW) == "vigente"
    assert cat.evidence_status(None, NOW) == "vigente"


# ---------------------------------------------------------------- API

def test_requires_login_and_role(client):
    assert client.get("/vendors").status_code == 401
    assert client.get("/vendors", headers=tok("viewer")).status_code == 403
    assert client.post("/vendors", headers=tok("analyst"), json={"name": "X"}).status_code == 403
    assert client.get("/vendors", headers=tok("analyst")).status_code == 200


def test_create_validates_input(client):
    h = tok()
    assert client.post("/vendors", headers=h, json={"name": "  "}).status_code == 422
    assert client.post("/vendors", headers=h, json={"name": "X", "domain": "no es dominio"}).status_code == 422
    assert client.post("/vendors", headers=h, json={"name": "X", "contact_email": "sin-arroba"}).status_code == 422
    assert client.post("/vendors", headers=h, json={"name": "X", "data_types": ["marcianos"]}).status_code == 422
    assert client.post("/vendors", headers=h, json={"name": "X", "criticality": "extrema"}).status_code == 422
    assert client.post("/vendors", headers=h, json={"name": "X" * 300}).status_code == 422
    r = client.post("/vendors", headers=h, json={"name": "Ok", "domain": "https://WWW.Ok.com/ruta"})
    assert r.status_code == 201 and r.json()["domain"] == "www.ok.com"


def test_duplicate_active_name_is_409(client):
    mk_vendor(client)
    r = client.post("/vendors", headers=tok(), json={"name": " nube sa "})
    assert r.status_code == 409 and "Ya existe" in r.json()["detail"]


def test_new_vendor_is_unassessed_and_listed(client):
    v = mk_vendor(client)
    assert v["risk"]["level"] == "unassessed"
    lst = client.get("/vendors", headers=tok()).json()
    assert [x["name"] for x in lst] == ["Nube SA"]
    s = client.get("/vendors/summary", headers=tok()).json()
    assert s["total"] == 1 and s["without_assessment_critical_or_high"] == 1


def test_full_questionnaire_flow_scores_the_vendor(client):
    v = mk_vendor(client, criticality="critical")
    token, r = send_and_answer(client, v["id"], answers("yes"))
    assert r.status_code == 201, r.text
    d = client.get(f"/vendors/{v['id']}", headers=tok()).json()
    assert d["risk"]["level"] == "low" and d["risk"]["effective_score"] == 100.0
    assert d["assessments"][0]["status"] == "completed" and d["assessments"][0]["respondent_email"] == "pedro@nube.com"
    # un link se usa una sola vez
    again = client.post(f"/public/vendor-assessments/{token}", json={
        "respondent_name": "Otro", "respondent_email": "o@nube.com", "answers": answers("no")})
    assert again.status_code == 409
    assert client.get(f"/public/vendor-assessments/{token}").json()["state"] == "completed"


def test_bad_vendor_scores_critical(client):
    v = mk_vendor(client, criticality="critical")
    _t, r = send_and_answer(client, v["id"], answers("no"))
    assert r.status_code == 201
    d = client.get(f"/vendors/{v['id']}", headers=tok()).json()
    assert d["risk"]["level"] == "critical" and d["risk"]["effective_score"] == 0.0


def test_public_link_requires_valid_token_and_full_answers(client):
    assert client.get("/public/vendor-assessments/inventado").status_code == 404
    assert client.post("/public/vendor-assessments/inventado", json={
        "respondent_name": "Pedro", "respondent_email": "p@x.com", "answers": answers()}).status_code == 404
    v = mk_vendor(client)
    token, r = send_and_answer(client, v["id"], {"gov-1": {"answer": "yes"}})
    assert r.status_code == 422 and "Faltan" in r.json()["detail"]
    r = client.post(f"/public/vendor-assessments/{token}", json={
        "respondent_name": "P", "respondent_email": "p@x.com", "answers": answers()})
    assert r.status_code == 422  # nombre muy corto
    r = client.post(f"/public/vendor-assessments/{token}", json={
        "respondent_name": "Pedro", "respondent_email": "no-es-mail", "answers": answers()})
    assert r.status_code == 422
    pub = client.get(f"/public/vendor-assessments/{token}").json()
    assert pub["state"] == "sent" and len(pub["questions"]) == 24 and pub["vendor_name"] == "Nube SA"
    assert "weight" not in json.dumps(pub) and "knockout" not in json.dumps(pub)


def test_token_is_stored_hashed_only(client):
    v = mk_vendor(client)
    r = client.post(f"/vendors/{v['id']}/assessments", headers=tok(), json={})
    token = r.json()["token"]
    detail = client.get(f"/vendors/{v['id']}", headers=tok()).text
    assert token not in detail
    assert len(token) >= 40


def test_expired_and_cancelled_links_are_rejected(client):
    v = mk_vendor(client)
    r = client.post(f"/vendors/{v['id']}/assessments", headers=tok(), json={})
    token, aid = r.json()["token"], r.json()["id"]
    assert client.post(f"/vendors/{v['id']}/assessments/{aid}/cancel", headers=tok()).status_code == 200
    assert client.post(f"/vendors/{v['id']}/assessments/{aid}/cancel", headers=tok()).status_code == 409
    got = client.get(f"/public/vendor-assessments/{token}").json()
    assert got["state"] == "cancelled" and got["questions"] == []
    sub = client.post(f"/public/vendor-assessments/{token}", json={
        "respondent_name": "Pedro", "respondent_email": "p@x.com", "answers": answers()})
    assert sub.status_code == 410


def test_expired_link_by_date(client):
    from sqlalchemy import update
    from app.vendor_models import VendorAssessment
    from backend.shared.database import get_db as gdb
    v = mk_vendor(client)
    r = client.post(f"/vendors/{v['id']}/assessments", headers=tok(), json={"days": 1})
    token = r.json()["token"]

    async def expire():
        gen = main.app.dependency_overrides[gdb]()
        s = await gen.__anext__()
        await s.execute(update(VendorAssessment).values(expires_at=datetime.now(timezone.utc) - timedelta(days=1)))
        await s.commit()
        await gen.aclose()

    asyncio.run(expire())
    assert client.get(f"/public/vendor-assessments/{token}").json()["state"] == "expired"
    assert client.post(f"/public/vendor-assessments/{token}", json={
        "respondent_name": "Pedro", "respondent_email": "p@x.com", "answers": answers()}).status_code == 410


def test_offboarded_vendor_cannot_receive_new_questionnaires(client):
    v = mk_vendor(client)
    assert client.patch(f"/vendors/{v['id']}", headers=tok(), json={"status": "offboarded"}).status_code == 200
    assert client.post(f"/vendors/{v['id']}/assessments", headers=tok(), json={}).status_code == 409
    assert client.get("/vendors", headers=tok()).json() == []
    assert len(client.get("/vendors?include_offboarded=true", headers=tok()).json()) == 1


def test_evidence_lifecycle_and_validation(client):
    v = mk_vendor(client)
    h = tok()
    ok = client.post(f"/vendors/{v['id']}/evidence", headers=h, json={
        "kind": "iso27001", "title": "Certificado ISO 27001", "valid_until": (datetime.now(timezone.utc) + timedelta(days=300)).isoformat(),
        "document_sha256": "a" * 64, "reference_url": "https://nube.com/iso.pdf"})
    assert ok.status_code == 201 and ok.json()["status"] == "vigente"
    assert client.post(f"/vendors/{v['id']}/evidence", headers=h, json={"kind": "iso27001", "title": "x"}).status_code == 422
    assert client.post(f"/vendors/{v['id']}/evidence", headers=h, json={
        "kind": "pentest", "title": "Pentest 2026", "document_sha256": "zz"}).status_code == 422
    assert client.post(f"/vendors/{v['id']}/evidence", headers=h, json={
        "kind": "pentest", "title": "Pentest 2026", "reference_url": "javascript:alert(1)"}).status_code == 422
    assert client.post(f"/vendors/{v['id']}/evidence", headers=h, json={
        "kind": "pentest", "title": "Pentest 2026", "issued_at": "2026-05-01", "valid_until": "2026-01-01"}).status_code == 422
    assert client.post(f"/vendors/{v['id']}/evidence", headers=h, json={"kind": "magia", "title": "Cosa rara"}).status_code == 422
    d = client.get(f"/vendors/{v['id']}", headers=h).json()
    assert d["evidence_counts"]["vigente"] == 1
    eid = d["evidence"][0]["id"]
    assert client.delete(f"/vendors/{v['id']}/evidence/{eid}", headers=h).status_code == 204
    assert client.delete(f"/vendors/{v['id']}/evidence/{eid}", headers=h).status_code == 404


def test_valid_evidence_raises_the_effective_score(client):
    v = mk_vendor(client, criticality="critical")
    send_and_answer(client, v["id"], answers("partial"))
    base = client.get(f"/vendors/{v['id']}", headers=tok()).json()["risk"]["effective_score"]
    client.post(f"/vendors/{v['id']}/evidence", headers=tok(), json={
        "kind": "soc2", "title": "Informe SOC 2 Tipo II", "valid_until": (datetime.now(timezone.utc) + timedelta(days=200)).isoformat()})
    after = client.get(f"/vendors/{v['id']}", headers=tok()).json()["risk"]["effective_score"]
    assert after == base + 5.0


def test_organizations_are_isolated(client):
    v = mk_vendor(client)
    assert client.get(f"/vendors/{v['id']}", headers=tok(org=B)).status_code == 404
    assert client.get("/vendors", headers=tok(org=B)).json() == []
    assert client.patch(f"/vendors/{v['id']}", headers=tok(org=B), json={"notes": "x"}).status_code == 404
    assert client.post(f"/vendors/{v['id']}/assessments", headers=tok(org=B), json={}).status_code == 404
    assert client.post(f"/vendors/{v['id']}/evidence", headers=tok(org=B), json={"kind": "dpa", "title": "DPA firmado"}).status_code == 404
    # el mismo nombre en otra organizacion es valido
    assert client.post("/vendors", headers=tok(org=B), json={"name": "Nube SA"}).status_code == 201


def test_csv_neutralizes_formulas(client):
    mk_vendor(client, name="=HYPERLINK(\"http://x\")")
    r = client.get("/vendors/report.csv", headers=tok())
    assert r.status_code == 200
    body = r.content.decode("utf-8-sig")
    assert "\n'=HYPERLINK" in body or ",'=HYPERLINK" in body or body.splitlines()[1].startswith("\"'=HYPERLINK") or "'=HYPERLINK" in body
    assert "\n=HYPERLINK" not in body


def test_events_land_in_the_custody_chain_and_chain_stays_valid(client):
    v = mk_vendor(client)
    send_and_answer(client, v["id"], answers("yes"))
    client.post(f"/vendors/{v['id']}/evidence", headers=tok(), json={"kind": "dpa", "title": "DPA firmado"})
    r = client.get("/custody/entries?limit=50", headers=tok())
    assert r.status_code == 200
    kinds = [e["event_type"] for e in r.json()["items"]]
    for expected in ("vendor.created", "vendor.assessment_sent", "vendor.assessment_completed", "vendor.evidence_added"):
        assert expected in kinds
    assert client.get("/custody/verify", headers=tok()).json()["ok"] is True


def test_attestation_is_signed_and_verifiable_without_tero(client, tmp_path):
    v = mk_vendor(client, criticality="critical")
    send_and_answer(client, v["id"], answers("no"))
    assert client.get("/vendors/attestation", headers=tok("analyst")).status_code == 403
    r = client.get("/vendors/attestation", headers=tok())
    assert r.status_code == 200
    doc = r.json()
    assert doc["kind"] == "vendor" and doc["body"]["summary"]["high_or_critical_risk"] == 1
    assert core.verify_attestation(doc)["ok"] is True
    assert ver.verify_attestation(doc)["ok"] is True
    doc["body"]["vendors"][0]["risk_level"] = "low"  # manipulado
    assert ver.verify_attestation(doc)["ok"] is False
    assert core.verify_attestation(doc)["ok"] is False
