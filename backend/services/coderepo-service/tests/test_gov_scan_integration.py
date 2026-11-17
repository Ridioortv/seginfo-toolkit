"""El escaneo real de un repositorio alimenta la gobernanza (git real, gitleaks/trivy simulados)."""
import shutil

from sqlalchemy import select

from app import ledger, services
from app.gov_models import CodeChange
from app.models import RepoScanStatus, RepoTarget, SecretFinding, SecretSeverity
from tests.gov_helpers import make_repo, run_db

COMMITS = [
    ("feat: base", {"src/a.py": "x = 1\n"}, "Ana", "ana@acme.com"),
    ("feat: con IA\n\nCo-Authored-By: Copilot <copilot@github.com>", {"src/b.py": "import os\nos.system(cmd)\n"}, "Ana", "ana@acme.com"),
]


def _patch(monkeypatch, repo, leaks=()):
    async def fake_clone(url, branch, token, dest):
        shutil.copytree(repo, dest, dirs_exist_ok=True)

    async def fake_gitleaks(path, warnings=None):
        return list(leaks)

    async def fake_trivy(path, name, warnings=None):
        return []

    monkeypatch.setattr(services, "_clone_repo", fake_clone)
    monkeypatch.setattr(services, "_run_gitleaks", fake_gitleaks)
    monkeypatch.setattr(services, "_run_trivy_fs", fake_trivy)


def test_scan_records_changes_and_second_scan_adds_nothing(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, COMMITS)
    _patch(monkeypatch, repo)

    async def body(factory):
        async with factory() as db:
            t = RepoTarget(name="r", repo_url="https://github.com/o/r", branch="main", organization_id="o1")
            db.add(t)
            await db.commit()
            tid = t.id
        await services.run_repo_scan_now(factory, tid)
        await services.run_repo_scan_now(factory, tid)
        async with factory() as db:
            target = await db.get(RepoTarget, tid)
            changes = (await db.execute(select(CodeChange).order_by(CodeChange.committed_at))).scalars().all()
            return target, changes, await ledger.verify_chain(db, "o1")

    target, changes, verify = run_db(body)
    assert target.last_scan_status == RepoScanStatus.ok and target.last_scan_error == ""
    assert [c.origin for c in changes] == ["human", "mixed"] and changes[1].ai_tool == "GitHub Copilot"
    assert changes[1].findings_json.count("os-system") == 1
    assert verify["ok"] and verify["entries"] == 2 + 2  # 2 cambios + 1 resumen por cada escaneo


def test_gitleaks_secret_is_linked_to_its_commit(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, COMMITS)

    async def body(factory):
        async with factory() as db:
            t = RepoTarget(name="r", repo_url="https://github.com/o/r", branch="main", organization_id="o1")
            db.add(t)
            await db.commit()
            return t.id

    import subprocess
    sha = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    leak = {"rule_id": "aws-access-token", "description": "AWS", "file_path": "src/b.py", "start_line": 2,
            "commit_hash": sha, "severity": SecretSeverity.critical, "match_redacted": "AKIA****"}
    _patch(monkeypatch, repo, [leak])

    async def go(factory):
        tid = await body(factory)
        await services.run_repo_scan_now(factory, tid)
        async with factory() as db:
            ch = (await db.execute(select(CodeChange).where(CodeChange.commit_sha == sha))).scalars().one()
            secrets = (await db.execute(select(SecretFinding))).scalars().all()
            return ch, secrets

    ch, secrets = run_db(go)
    assert len(secrets) == 1 and '"source":"gitleaks"' in ch.findings_json and '"severity":"critical"' in ch.findings_json


def test_governance_failure_does_not_break_the_scan(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, COMMITS)
    _patch(monkeypatch, repo)

    async def boom(*a, **k):
        raise RuntimeError("falla de gobernanza")

    from app import governance
    monkeypatch.setattr(governance, "ingest_history", boom)

    async def go(factory):
        async with factory() as db:
            t = RepoTarget(name="r", repo_url="https://github.com/o/r", branch="main", organization_id="o1")
            db.add(t)
            await db.commit()
            tid = t.id
        await services.run_repo_scan_now(factory, tid)
        async with factory() as db:
            return await db.get(RepoTarget, tid)

    t = run_db(go)
    assert t.last_scan_status == RepoScanStatus.ok and "gobernanza" in t.last_scan_error
