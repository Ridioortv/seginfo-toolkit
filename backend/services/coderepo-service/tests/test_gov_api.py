"""API de gobernanza de punta a punta (FastAPI + SQLite): permisos, aislamiento por organizacion,
compuerta para CI, revisiones, politicas, registro auditable y exportacion."""
import asyncio
import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import gov_models, main  # noqa: F401
from app.gov_models import LedgerEntry
from app.models import Base, RepoTarget
from backend.shared.database import get_db
from backend.shared.security import create_access_token

ORG_A, ORG_B = "org-a", "org-b"


def token(role="admin", org=ORG_A, email="admin@acme.com", sub="u1"):
    return {"Authorization": "Bearer " + create_access_token(sub, role, org_id=org, email=email)}


@pytest.fixture()
def env():
    path = os.path.join(tempfile.mkdtemp(prefix="gov-api-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as db:
            for rid, org in (("repo-a", ORG_A), ("repo-b", ORG_B)):
                db.add(RepoTarget(id=rid, name=rid, repo_url=f"https://github.com/acme/{rid}.git", branch="main", organization_id=org))
            await db.commit()

    asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app), Session
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


DIRTY_DIFF = "+++ b/src/pagos/cobro.py\n@@ -0,0 +1,2 @@\n+import subprocess\n+subprocess.run(cmd, shell=True)\n"


def test_requires_login_and_roles(env):
    c, _ = env
    assert c.get("/governance/metrics").status_code == 401
    assert c.get("/governance/changes", headers=token("viewer")).status_code == 200
    policy = {"name": "x", "mode": "enforce"}
    assert c.post("/governance/policies", json=policy, headers=token("viewer")).status_code == 403
    assert c.post("/governance/policies", json=policy, headers=token("analyst")).status_code == 403
    assert c.post("/governance/policies", json=policy, headers=token("soc_manager")).status_code == 201
    body = {"repo_target_id": "repo-a", "commit_sha": "a" * 40}
    assert c.post("/governance/gate/evaluate", json=body, headers=token("viewer")).status_code == 403


def test_policy_crud_validation_and_ledger(env):
    c, _ = env
    h = token()
    bad = c.post("/governance/policies", json={"name": "x", "mode": "bloquear"}, headers=h)
    assert bad.status_code == 422
    assert c.post("/governance/policies", json={"name": "x", "repo_target_id": "repo-b"}, headers=h).status_code == 404
    created = c.post("/governance/policies", headers=h, json={
        "name": "Pagos", "repo_target_id": "repo-a", "path_prefixes": "src/pagos/", "ai_policy": "restricted",
        "required_reviews": 1, "block_on_severity": "high", "mode": "observe"}).json()
    assert created["repo_name"] == "repo-a" and created["created_by"] == "admin@acme.com"
    upd = dict(created, mode="enforce")
    assert c.put(f"/governance/policies/{created['id']}", json=upd, headers=h).json()["mode"] == "enforce"
    assert c.put(f"/governance/policies/{created['id']}", json=upd, headers=token(org=ORG_B)).status_code == 404
    assert c.delete(f"/governance/policies/{created['id']}", headers=token(org=ORG_B)).status_code == 404
    assert c.delete(f"/governance/policies/{created['id']}", headers=h).status_code == 204
    assert c.get("/governance/policies", headers=h).json() == []
    events = [e["event_type"] for e in c.get("/governance/ledger", headers=h).json()["items"]]
    assert events == ["policy.deleted", "policy.updated", "policy.created"]
    updated = next(e for e in c.get("/governance/ledger", headers=h).json()["items"] if e["event_type"] == "policy.updated")
    assert updated["payload"]["before"]["mode"] == "observe" and updated["payload"]["after"]["mode"] == "enforce"


def test_ci_gate_blocks_then_review_unblocks_and_everything_is_audited(env):
    c, _ = env
    admin = token()
    c.post("/governance/policies", headers=admin, json={
        "name": "Pagos", "path_prefixes": "src/pagos/", "ai_policy": "restricted", "required_reviews": 1,
        "block_on_severity": "none", "mode": "enforce"})
    sha = "f" * 40
    body = {"repo_url": "https://github.com/Acme/repo-a", "commit_sha": sha, "origin": "ai", "ai_tool": "Cursor",
            "ai_model": "gpt-5", "prompt_ref": "cobro con tarjeta", "files": ["src/pagos/cobro.py"],
            "author_email": "ana@acme.com", "diff": DIRTY_DIFF}
    first = c.post("/governance/gate/evaluate", json=body, headers=admin)
    assert first.status_code == 200
    r = first.json()
    assert r["allowed"] is False and r["status"] == "blocked" and r["policy"] == "Pagos"
    assert [v["code"] for v in r["violations"]] == ["missing_review"]

    change_id = r["change_id"]
    self_review = c.post(f"/governance/changes/{change_id}/review", json={"decision": "approve"},
                         headers=token(email="ana@acme.com"))
    assert self_review.status_code == 403
    ok = c.post(f"/governance/changes/{change_id}/review", json={"decision": "approve", "comment": "revisado"},
                headers=token("analyst", email="luis@acme.com"))
    assert ok.status_code == 200 and ok.json()["allowed"] is True and ok.json()["status"] == "passed"
    again = c.post("/governance/gate/evaluate", json=body, headers=admin).json()
    assert again["allowed"] is True and again["change_id"] == change_id

    change = c.get(f"/governance/changes/{change_id}", headers=admin).json()
    assert change["origin"] == "ai" and change["review_status"] == "approved" and change["review_count"] == 1
    assert change["findings"][0]["rule_id"] == "shell-true" and change["files"] == ["src/pagos/cobro.py"]
    assert change["repo_name"] == "repo-a" and change["lines_added"] == 2

    verify = c.get("/governance/ledger/verify", headers=admin).json()
    assert verify["ok"] and verify["entries"] >= 5
    runs = c.get("/governance/gate/runs", headers=admin).json()
    assert [x["status"] for x in runs][-1] == "blocked" and runs[0]["status"] == "passed"

    declared = c.patch(f"/governance/changes/{change_id}", headers=admin, json={"origin": "human"})
    assert declared.status_code == 200
    assert c.get(f"/governance/changes/{change_id}", headers=admin).json()["detection"] == "declared"
    assert c.patch(f"/governance/changes/{change_id}", headers=admin, json={"origin": "robot"}).status_code == 422


def test_unknown_repo_and_isolation_between_organizations(env):
    c, _ = env
    assert c.post("/governance/gate/evaluate", headers=token(), json={"repo_target_id": "repo-b", "commit_sha": "a" * 40}).status_code == 404
    assert c.post("/governance/gate/evaluate", headers=token(), json={"repo_url": "https://github.com/x/y", "commit_sha": "a" * 40}).status_code == 404
    made = c.post("/governance/gate/evaluate", headers=token(), json={"repo_target_id": "repo-a", "commit_sha": "a" * 40}).json()
    assert c.get(f"/governance/changes/{made['change_id']}", headers=token(org=ORG_B)).status_code == 404
    assert c.post(f"/governance/changes/{made['change_id']}/review", json={"decision": "approve"}, headers=token(org=ORG_B)).status_code == 404
    assert c.get("/governance/changes", headers=token(org=ORG_B)).json() == {"total": 0, "items": []}
    assert c.get("/governance/ledger", headers=token(org=ORG_B)).json()["total"] == 0
    assert c.get("/governance/metrics", headers=token(org=ORG_B)).json()["totals"]["changes"] == 0


def test_changes_filters_and_pagination(env):
    c, _ = env
    h = token()
    for i, (origin, diff) in enumerate([("ai", DIRTY_DIFF), ("human", ""), ("ai", ""), ("mixed", "")]):
        c.post("/governance/gate/evaluate", headers=h, json={
            "repo_target_id": "repo-a", "commit_sha": f"{i}" * 40, "origin": origin, "diff": diff or None,
            "files": ["src/a.py"]})
    assert c.get("/governance/changes?origin=ai", headers=h).json()["total"] == 2
    assert c.get("/governance/changes?gate_status=observed_fail", headers=h).json()["total"] == 1
    page = c.get("/governance/changes?limit=2&offset=2", headers=h).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    assert c.get("/governance/changes?limit=500", headers=h).status_code == 422


def test_ledger_export_and_tamper_detection_through_the_api(env):
    c, Session = env
    h = token()
    for i in range(3):
        c.post("/governance/policies", headers=h, json={"name": f"p{i}"})
    exported = c.get("/governance/ledger/export?format=json", headers=h)
    assert exported.status_code == 200 and "attachment" in exported.headers["content-disposition"]
    data = exported.json()
    assert data["verification"]["ok"] and len(data["entries"]) == 3 and data["anchor"]["entries"] == 3
    csv_resp = c.get("/governance/ledger/export?format=csv", headers=h)
    assert csv_resp.text.splitlines()[0].startswith("seq,ts,event_type") and len(csv_resp.text.splitlines()) == 4
    assert c.get("/governance/ledger/export?format=xml", headers=h).status_code == 422

    anchor = c.get("/governance/ledger/anchor", headers=h).json()
    assert c.get(f"/governance/ledger/verify?expected_count=3&expected_head={anchor['head_hash']}", headers=h).json()["ok"]

    async def tamper():
        async with Session() as db:
            await db.execute(update(LedgerEntry).where(LedgerEntry.seq == 2).values(subject="otro"))
            await db.commit()
    asyncio.run(tamper())
    broken = c.get("/governance/ledger/verify", headers=h).json()
    assert broken["ok"] is False and broken["broken_at_seq"] == 2
    assert c.get("/governance/ledger/export?format=json", headers=h).json()["verification"]["ok"] is False


def test_connecting_a_repo_is_audited(env, monkeypatch):
    c, _ = env
    monkeypatch.setattr("app.services.repo_url_safety_error", lambda url: None)  # sin resolver DNS en el test
    h = token()
    r = c.post("/repos", headers=h, json={"name": "nuevo", "repo_url": "https://github.com/acme/nuevo", "branch": "main"})
    assert r.status_code == 201
    c.delete(f"/repos/{r.json()['id']}", headers=h)
    events = [e["event_type"] for e in c.get("/governance/ledger", headers=h).json()["items"]]
    assert events == ["repo.deleted", "repo.connected"]


def test_metrics_endpoint_params(env):
    c, _ = env
    h = token()
    c.post("/governance/gate/evaluate", headers=h, json={"repo_target_id": "repo-a", "commit_sha": "9" * 40, "origin": "ai", "diff": "+++ b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"})
    m = c.get("/governance/metrics?days=7&hours_per_ai_change=1.5", headers=h).json()
    assert m["totals"]["ai_changes"] == 1 and m["roi"]["estimated_hours_saved"] == 1.5 and m["window_days"] == 7
    assert c.get("/governance/metrics?days=0", headers=h).status_code == 422
