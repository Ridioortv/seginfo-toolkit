"""Consola multicliente: consolidado por cliente, orden por urgencia, usuarios suspendidos / sin datos, CSV seguro y roles."""
import asyncio
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import main
from app import partner_service as svc
from backend.shared.security import create_access_token

NOW = datetime(2026, 6, 30, 12, tzinfo=timezone.utc)
P = "org-partner"


def tok(role="admin", org=P, **extra):
    import backend.shared.security as sec
    from datetime import timedelta
    claims = {"role": role, "type": "access", "org_id": org, "email": "m@mssp.com", **extra}
    return {"Authorization": "Bearer " + sec.create_token("u1", timedelta(minutes=5), claims)}


def summary(status="stable", ch=0, kev=0, cases_open=1, overdue=0, exposure=5.0, attention=()):
    return {
        "status": status, "assets_count": 7, "exposure": {"total_score": exposure},
        "vulnerabilities": {"open_total": 10, "critical_high": ch, "kev": kev, "oldest_critical_high_days": 12},
        "cases": {"open": cases_open, "overdue": overdue, "opened": {"current": 3}},
        "remediation": {"mttr_real_hours": 40.0}, "exceptions": {"active": 2}, "vendors": {"high_or_critical_risk": 1},
        "attention": list(attention), "sources": {"vuln-service": {"ok": True, "error": ""}},
    }


def a(level, text="x"):
    return {"level": level, "code": text, "message": {"text": text, "args": []}, "link": ""}


C = lambda i, name, active=True: {"id": i, "name": name, "is_active": active, "users": 2, "subscription_expires_at": "2026-12-01T00:00:00+00:00"}


def test_client_row_counts_attention_and_hides_info_from_top():
    s = summary("attention", ch=4, kev=1, attention=[a("critical", "k"), a("warning", "w"), a("info", "i")])
    r = svc.client_row(C("1", "Acme"), s)
    assert r["status"] == "attention" and r["attention"] == {"critical": 1, "warning": 1, "info": 1}
    assert [x["code"] for x in r["top_attention"]] == ["k", "w"]
    assert r["critical_high"] == 4 and r["kev"] == 1 and r["assets"] == 7 and r["users"] == 2


def test_unreadable_and_suspended_clients_are_never_zeros():
    r = svc.client_row(C("1", "Caido"), None, "ConnectError")
    assert r["status"] == "unknown" and r["error"] == "ConnectError" and "open_total" not in r
    s = svc.client_row(C("2", "Suspendido", active=False), summary())
    assert s["status"] == "suspended" and "open_total" not in s


def test_sorting_attention_first_then_unknown_exposure_desc_and_suspended_last():
    rows = [svc.client_row(C("1", "Estable"), summary("stable", exposure=50)),
            svc.client_row(C("2", "Vigilar"), summary("watch", exposure=10)),
            svc.client_row(C("3", "Susp", False), None),
            svc.client_row(C("4", "Mal-chico"), summary("attention", exposure=5)),
            svc.client_row(C("5", "Mal-grande"), summary("attention", exposure=90)),
            svc.client_row(C("6", "Caido"), None, "X")]
    assert [r["name"] for r in svc.sort_rows(rows)] == ["Mal-grande", "Mal-chico", "Caido", "Vigilar", "Estable", "Susp"]


def test_totals_only_add_clients_that_were_read():
    rows = [svc.client_row(C("1", "A"), summary("attention", ch=3, kev=1, overdue=2)),
            svc.client_row(C("2", "B"), summary("stable", ch=1)),
            svc.client_row(C("3", "C"), None, "X"), svc.client_row(C("4", "D", False), None)]
    t = svc.totals(rows)
    assert t["clients"] == 4 and t["active"] == 3 and t["critical_high"] == 4 and t["kev"] == 1 and t["cases_overdue"] == 2
    assert t["by_status"] == {"attention": 1, "watch": 0, "stable": 1, "unknown": 1, "suspended": 1}
    assert t["users"] == 8 and t["assets"] == 14


def test_csv_neutralizes_formulas_and_has_totals():
    rows = [svc.client_row(C("1", '=HYPERLINK("http://evil","x")'), summary("stable")),
            svc.client_row(C("2", "+cmd|calc"), summary("watch"))]
    data = {"generated_at": NOW.isoformat(), "days": 30, "partner": {"id": P, "name": "MSSP"}, "totals": svc.totals(rows), "clients": rows}
    text = svc.usage_csv(data)
    assert text.startswith("﻿")
    assert "'=HYPERLINK" in text and "'+cmd" in text
    assert "\r\n=HYPERLINK" not in text and ",=HYPERLINK" not in text
    assert "TOTAL" in text and "Estable" in text and "A vigilar" in text


@pytest.fixture()
def fake(monkeypatch):
    svc._CACHE.clear()
    calls = {"summary": 0, "clients": 0}
    clients = [C("c1", "Uno"), C("c2", "Dos"), C("c3", "Tres", False), C("c4", "Cuatro")]

    async def fetch(org):
        calls["clients"] += 1
        if org != P:
            raise svc.PartnerError(403, "Tu organizacion no es un partner")
        return {"id": P, "name": "MSSP"}, clients

    async def lean(org, days, now):
        calls["summary"] += 1
        if org == "c4":
            raise RuntimeError("boom")
        return summary("attention" if org == "c1" else "stable", ch=5 if org == "c1" else 0)

    monkeypatch.setattr(svc, "fetch_clients", fetch)
    monkeypatch.setattr(svc, "lean_summary", lean)
    return calls


def test_overview_isolates_failures_skips_suspended_and_caches(fake):
    d = asyncio.run(svc.overview(P, 30, NOW))
    by = {r["id"]: r for r in d["clients"]}
    assert by["c1"]["status"] == "attention" and by["c2"]["status"] == "stable"
    assert by["c3"]["status"] == "suspended" and by["c4"]["status"] == "unknown" and by["c4"]["error"] == "RuntimeError"
    assert fake["summary"] == 3  # el suspendido no se calcula
    assert d["clients"][0]["id"] == "c1" and d["clients"][-1]["id"] == "c3"
    asyncio.run(svc.overview(P, 30, NOW))
    assert fake["clients"] == 2 and fake["summary"] == 4  # la lista se pide siempre; solo el cliente que fallo se reintenta
    asyncio.run(svc.overview(P, 90, NOW))
    assert fake["summary"] == 7  # otro periodo: se calcula de nuevo


def test_new_and_suspended_clients_show_up_immediately_despite_cache(fake, monkeypatch):
    asyncio.run(svc.overview(P, 30, NOW))
    base_calls = fake["summary"]
    bigger = [C("c1", "Uno RENOMBRADO"), C("c2", "Dos", active=False), C("c5", "Nuevo")]

    async def fetch(org):
        return {"id": P, "name": "MSSP"}, bigger
    monkeypatch.setattr(svc, "fetch_clients", fetch)
    d = asyncio.run(svc.overview(P, 30, NOW))
    by = {r["id"]: r for r in d["clients"]}
    assert by["c1"]["name"] == "Uno RENOMBRADO" and by["c2"]["status"] == "suspended" and by["c5"]["status"] == "stable"
    assert "c3" not in by and "c4" not in by
    assert fake["summary"] == base_calls + 1  # solo el cliente nuevo se calcula; c1 sale de la cache


def test_routes_roles_and_isolation(fake):
    c = TestClient(main.app)
    r = c.get("/partner/overview", headers=tok("viewer"))
    assert r.status_code == 200 and r.json()["totals"]["clients"] == 4
    assert c.get("/partner/overview").status_code == 401
    assert c.get("/partner/overview?days=3", headers=tok()).status_code == 422
    # otra organizacion (no partner): 403 y no filtra nada
    r = c.get("/partner/overview", headers=tok("admin", org="org-comun"))
    assert r.status_code == 403
    # quien "entro" a un cliente no puede ver la consola, ni siquiera con el org_id del partner inventado
    entered = tok("soc_manager", org="c1", partner_org_id=P)
    assert c.get("/partner/overview", headers=entered).status_code == 403
    assert c.get("/partner/usage.csv", headers=entered).status_code == 403
    forged = tok("admin", org=P, partner_org_id=P)
    assert c.get("/partner/overview", headers=forged).status_code == 403


def test_usage_csv_roles(fake):
    c = TestClient(main.app)
    assert c.get("/partner/usage.csv", headers=tok("analyst")).status_code == 403
    assert c.get("/partner/usage.csv", headers=tok("viewer")).status_code == 403
    r = c.get("/partner/usage.csv", headers=tok("soc_manager"))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "uso-por-cliente-" in r.headers["content-disposition"] and "Uno" in r.text and "Suspendido" in r.text


def test_auth_down_is_502_not_empty(monkeypatch):
    svc._CACHE.clear()

    async def fetch(org):
        raise svc.PartnerError(502, "No pude consultar la lista de clientes. Proba de nuevo en un momento.")
    monkeypatch.setattr(svc, "fetch_clients", fetch)
    r = TestClient(main.app).get("/partner/overview", headers=tok())
    assert r.status_code == 502
