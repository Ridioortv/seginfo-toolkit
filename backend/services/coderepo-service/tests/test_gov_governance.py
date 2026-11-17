"""Politicas, compuerta, revision humana, ingesta desde un repositorio git real y metricas."""
import pytest
from sqlalchemy import select

from app import governance as g, ledger
from app.gov_models import CodeChange, GateRun, GovernancePolicy
from app.models import RepoTarget
from tests.gov_helpers import make_repo, run_db

ORG = "org-1"
SECRET_LINE = 'password = "SuperSecreta123"\n'


def _policy(**kw):
    base = dict(id="p1", organization_id=ORG, name="Base", repo_target_id=None, path_prefixes="", ai_policy="allowed",
                required_reviews=0, block_on_severity="high", mode="observe", is_active=True)
    base.update(kw)
    return GovernancePolicy(**base)


def test_resolve_policy_picks_most_restrictive_that_applies():
    policies = [
        _policy(id="a", name="General", mode="observe"),
        _policy(id="b", name="Pagos", path_prefixes="src/pagos/, src/billing", ai_policy="forbidden", mode="enforce"),
        _policy(id="c", name="Otro repo", repo_target_id="r2", ai_policy="forbidden", mode="enforce"),
        _policy(id="d", name="Apagada", ai_policy="forbidden", is_active=False),
    ]
    assert g.resolve_policy(policies, "r1", ["src/app.py"]).name == "General"
    assert g.resolve_policy(policies, "r1", ["src/pagos/cobro.py", "x.py"]).name == "Pagos"
    assert g.resolve_policy(policies, "r1", ["src/billing/a.py"]).name == "Pagos"
    assert g.resolve_policy(policies, "r2", ["src/app.py"]).name == "Otro repo"
    assert g.resolve_policy([], "r1", []).name.startswith("Base")


def _eval(origin, findings=(), review="none", approvals=0, **policy):
    eff = g.resolve_policy([_policy(**policy)], "r1", [])
    return g.evaluate_change(origin, list(findings), review, approvals, eff)


HIGH = {"severity": "high", "description": "shell=True", "rule_id": "shell-true"}
LOW = {"severity": "low", "description": "debug", "rule_id": "debug-on"}


def test_evaluate_enforce_blocks_and_observe_only_flags():
    assert _eval("human", [HIGH], mode="enforce")[0] == "blocked"
    assert _eval("human", [HIGH], mode="observe")[0] == "observed_fail"
    assert _eval("human", [LOW], mode="enforce")[0] == "passed"
    assert _eval("human", [HIGH], mode="enforce", block_on_severity="none")[0] == "passed"
    assert _eval("human", [LOW], mode="enforce", block_on_severity="medium")[0] == "passed"


def test_ai_rules_only_apply_to_ai_code():
    status, v = _eval("ai", ai_policy="forbidden", mode="enforce")
    assert status == "blocked" and v[0]["code"] == "ai_forbidden"
    assert _eval("human", ai_policy="forbidden", mode="enforce")[0] == "passed"
    status, v = _eval("mixed", ai_policy="restricted", mode="enforce")
    assert status == "blocked" and v[0]["code"] == "missing_review"
    assert _eval("mixed", ai_policy="restricted", mode="enforce", approvals=1)[0] == "passed"
    assert _eval("ai", required_reviews=2, mode="enforce", approvals=1)[0] == "blocked"
    assert _eval("ai", required_reviews=2, mode="enforce", approvals=2)[0] == "passed"
    assert _eval("human", required_reviews=2, mode="enforce")[0] == "passed"
    assert _eval("human", review="rejected", mode="enforce")[1][0]["code"] == "review_rejected"


async def _target(factory, name="repo-a"):
    async with factory() as db:
        t = RepoTarget(name=name, repo_url=f"https://github.com/o/{name}", branch="main", organization_id=ORG)
        db.add(t)
        await db.commit()
        return t.id


def _fake_git(repo):
    return lambda *_: None


COMMITS = [
    ("feat: pantalla de login", {"src/login.py": "def login():\n    return True\n"}, "Ana", "ana@acme.com"),
    ("feat: cobros\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>\n\nAI-Prompt: agregar cobro con tarjeta",
     {"src/pagos/cobro.py": "import subprocess\nsubprocess.run(cmd, shell=True)\n" + SECRET_LINE}, "Ana", "ana@acme.com"),
    ("chore: generado por agente\n\nAI-Origin: ai\nAI-Tool: Aider",
     {"src/util.py": "x = 1\ny = 2\n"}, "Luis", "luis@acme.com"),
]


def test_ingest_real_git_history_counts_provenance_and_gates(tmp_path):
    repo = make_repo(tmp_path, COMMITS)

    async def go(factory):
        tid = await _target(factory)
        async with factory() as db:
            db.add(_policy(id="pol-pagos", name="Pagos", path_prefixes="src/pagos/", ai_policy="restricted",
                           mode="enforce", block_on_severity="high"))
            await db.commit()
        async with factory() as db:
            target = await db.get(RepoTarget, tid)
            stats = await g.ingest_history(db, target, repo, [])
            await db.commit()
            again = await g.ingest_history(db, target, repo, [])  # idempotente: no duplica
            await db.commit()
            rows = (await db.execute(select(CodeChange).order_by(CodeChange.committed_at))).scalars().all()
            verify = await ledger.verify_chain(db, ORG)
            total, entries = await ledger.list_entries(db, ORG, limit=100)
            return stats, again, rows, verify, [e.event_type for e in entries]

    stats, again, rows, verify, events = run_db(go)
    assert stats["new_changes"] == 3 and stats["ai_changes"] == 2 and stats["blocked"] == 1
    assert again["new_changes"] == 0
    login, cobro, util = rows
    assert (login.origin, login.detection, login.gate_status) == ("human", "default", "passed")
    assert (cobro.origin, cobro.ai_tool, cobro.ai_model) == ("mixed", "Claude", "Claude Sonnet 5.5")
    assert cobro.prompt_ref == "agregar cobro con tarjeta"
    assert cobro.gate_status == "blocked" and cobro.gate_policy_name == "Pagos"
    assert cobro.lines_added == 3 and cobro.files_changed == 1
    assert (util.origin, util.ai_tool, util.lines_added) == ("ai", "Aider", 2)
    assert util.gate_status == "passed"  # sin hallazgos y la politica base permite IA
    assert verify["ok"] and verify["entries"] == len(events)
    assert events.count("change.recorded") == 3 and events.count("scan.ingested") == 2


def test_secret_from_gitleaks_is_attached_and_regated(tmp_path):
    repo = make_repo(tmp_path, COMMITS[:1])

    async def go(factory):
        tid = await _target(factory)
        async with factory() as db:
            db.add(_policy(mode="enforce", block_on_severity="critical"))
            await db.commit()
        async with factory() as db:
            target = await db.get(RepoTarget, tid)
            await g.ingest_history(db, target, repo, [])
            change = (await db.execute(select(CodeChange))).scalars().one()
            first = change.gate_status
            leaked = [{"commit_hash": change.commit_sha, "rule_id": "aws-access-token", "severity": "critical",
                       "description": "AWS key", "file_path": "src/login.py", "start_line": 1, "match_redacted": "AKIA****"}]
            stats = await g.ingest_history(db, target, repo, leaked)
            await db.commit()
            again = await g.ingest_history(db, target, repo, leaked)  # mismo secreto: no se suma dos veces
            return first, stats, again, change.gate_status

    first, stats, again, final = run_db(go)
    assert first == "passed" and stats["updated_changes"] == 1 and final == "blocked"
    assert again["updated_changes"] == 0


def test_review_flow_unblocks_and_self_review_is_refused_when_enforced(tmp_path):
    repo = make_repo(tmp_path, COMMITS[1:2])

    async def go(factory):
        tid = await _target(factory)
        async with factory() as db:
            db.add(_policy(mode="enforce", ai_policy="restricted", required_reviews=2, block_on_severity="critical"))
            await db.commit()
        async with factory() as db:
            await g.ingest_history(db, await db.get(RepoTarget, tid), repo, [])
            change = (await db.execute(select(CodeChange))).scalars().one()
            out = {"start": change.gate_status}
            try:
                await g.review_change(db, change, "approve", "ok", "ana@acme.com")  # la autora
            except g.GovernanceError as exc:
                out["self"] = exc.status_code
            r1 = await g.review_change(db, change, "approve", "", "luis@acme.com")
            out["after_one"] = r1["status"]
            await g.review_change(db, change, "approve", "", "luis@acme.com")  # la misma persona no suma dos veces
            out["same_person_twice"] = change.review_count
            r2 = await g.review_change(db, change, "approve", "", "marta@acme.com")
            out["after_two"] = r2["status"]
            r3 = await g.review_change(db, change, "reject", "no", "pedro@acme.com")
            out["after_reject"] = r3["status"]
            await db.commit()
            total, entries = await ledger.list_entries(db, ORG, limit=100)
            out["reviews_logged"] = [e.event_type for e in entries].count("change.reviewed")
            out["runs"] = len((await db.execute(select(GateRun))).scalars().all())
            return out

    out = run_db(go)
    assert out["start"] == "blocked" and out["self"] == 403
    assert out["after_one"] == "blocked" and out["same_person_twice"] == 1
    assert out["after_two"] == "passed" and out["after_reject"] == "blocked"
    assert out["reviews_logged"] == 4  # luis, luis, marta y pedro (la aprobacion propia rechazada no se registra)
    assert out["runs"] >= 5


def test_declare_origin_is_logged_with_before_and_after(tmp_path):
    repo = make_repo(tmp_path, COMMITS[:1])

    async def go(factory):
        tid = await _target(factory)
        async with factory() as db:
            await g.ingest_history(db, await db.get(RepoTarget, tid), repo, [])
            change = (await db.execute(select(CodeChange))).scalars().one()
            with pytest.raises(g.GovernanceError):
                await g.declare_origin(db, change, "robot", "", "", "", "ana@acme.com")
            await g.declare_origin(db, change, "mixed", "Cursor", "gpt-5", "refactor del login", "ana@acme.com")
            await db.commit()
            _, entries = await ledger.list_entries(db, ORG, limit=5, event_type="change.origin_declared")
            return change, entries[0].payload

    change, payload = run_db(go)
    assert (change.origin, change.ai_tool, change.detection) == ("mixed", "Cursor", "declared")
    assert '"before":{"ai_model":"","ai_tool":"","origin":"human"' in payload and '"origin":"mixed"' in payload


def test_ci_evaluate_creates_change_scans_diff_and_answers_allowed():
    diff = "+++ b/app.py\n@@ -0,0 +1,2 @@\n+import os\n+os.system(cmd)\n+requests.get(u, verify=False)\n"

    async def go(factory):
        tid = await _target(factory)
        async with factory() as db:
            db.add(_policy(mode="enforce", ai_policy="forbidden"))
            await db.commit()
        async with factory() as db:
            target = await db.get(RepoTarget, tid)
            body = {"commit_sha": "c" * 40, "origin": "ai", "ai_tool": "Cursor", "diff": diff, "files": ["app.py"],
                    "author_email": "ana@acme.com", "message": "feat: x"}
            first = await g.evaluate_external(db, target, body, "ci@acme.com")
            clean = await g.evaluate_external(db, target, {"commit_sha": "d" * 40, "origin": "human", "diff": "+++ b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"}, "ci")
            repeat = await g.evaluate_external(db, target, body, "ci@acme.com")  # mismo commit: reutiliza el cambio
            await db.commit()
            count = len((await db.execute(select(CodeChange))).scalars().all())
            return first, clean, repeat, count

    first, clean, repeat, count = run_db(go)
    assert first["allowed"] is False and first["status"] == "blocked"
    assert {v["code"] for v in first["violations"]} == {"ai_forbidden", "findings_over_threshold"}
    assert clean["allowed"] is True and clean["status"] == "passed"
    assert repeat["change_id"] == first["change_id"] and count == 2


def test_observe_mode_allows_but_flags():
    async def go(factory):
        tid = await _target(factory)
        async with factory() as db:
            target = await db.get(RepoTarget, tid)
            return await g.evaluate_external(db, target, {
                "commit_sha": "e" * 40, "diff": "+++ b/a.py\n@@ -0,0 +1 @@\n+x = eval(y)\n"}, "ci")
    result = run_db(go)
    assert result["allowed"] is True and result["status"] == "observed_fail" and result["mode"] == "observe"


def test_metrics_compare_ai_and_human_and_scope_by_organization(tmp_path):
    repo = make_repo(tmp_path, COMMITS)

    async def go(factory):
        tid = await _target(factory)
        other = await _target(factory, "otra-org")
        async with factory() as db:
            db.add(_policy(id="p9", name="Pagos", path_prefixes="src/pagos/", mode="enforce", ai_policy="restricted"))
            await db.commit()
        async with factory() as db:
            target = await db.get(RepoTarget, tid)
            await g.ingest_history(db, target, repo, [])
            foreign = await db.get(RepoTarget, other)
            foreign.organization_id = "org-2"
            await db.flush()
            await g.ingest_history(db, foreign, repo, [])  # la otra organizacion no debe mezclarse
            await db.commit()
            cobro = (await db.execute(select(CodeChange).where(CodeChange.organization_id == ORG, CodeChange.message.like("feat: cobros%")))).scalars().one()
            await g.review_change(db, cobro, "approve", "", "luis@acme.com")
            await db.commit()
            return await g.compute_metrics(db, "org-1", 36500, hours_per_ai_change=2), await g.compute_metrics(db, "org-2", 36500)

    m, m2 = run_db(go)
    t = m["totals"]
    assert (t["changes"], t["human"], t["mixed"], t["ai"]) == (3, 1, 1, 1) and t["ai_changes"] == 2
    assert t["ai_share_pct"] == 66.7 and t["lines_added"] == 2 + 3 + 2 and t["ai_lines"] == 5
    assert m["review"] == {"ai_changes_needing_review": 2, "ai_changes_approved": 1, "coverage_pct": 50.0,
                           "avg_review_hours": m["review"]["avg_review_hours"]}
    assert m["findings"]["in_ai_code"] >= 2 and m["findings"]["in_human_code"] == 0
    assert m["findings"]["per_1000_lines_ai"] > 0 and m["findings"]["per_1000_lines_human"] == 0
    assert m["gate"] == {"passed": 2, "blocked": 1, "observed_fail": 0}  # cobros sigue bloqueado: aprobado, pero tiene shell=True
    assert m["roi"]["estimated_hours_saved"] == 4.0
    assert {x["tool"] for x in m["tools"]} == {"Claude", "Aider"}
    assert m["by_repo"][0]["repo"] == "repo-a" and m["by_repo"][0]["ai_changes"] == 2
    assert len(m["weekly"]) >= 1 and m["ledger"]["entries"] >= 5
    assert m2["totals"]["changes"] == 3  # sus propios cambios, no los de la org 1
