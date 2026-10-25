"""Logica de la app "Gobernanza de codigo con IA": ingesta de procedencia desde el historial de git,
politicas por equipo, compuerta de seguridad, revisiones humanas y metricas.

Todo lo que cambia el estado de gobernanza (cambio registrado, origen declarado, revision, politica,
evaluacion de la compuerta) deja una entrada en el registro auditable (app/ledger.py)."""
import asyncio
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.logging import configure_logging
from app import ledger, provenance
from app.gov_models import CodeChange, GateRun, GovernancePolicy
from app.models import RepoTarget

logger = configure_logging("coderepo-service")

MAX_NEW_COMMITS = int(os.getenv("CODEREPO_GOV_MAX_COMMITS", "300"))
MAX_DIFF_BYTES = 500_000
AI_ORIGINS = ("ai", "mixed")
SEV_RANK = provenance.SEVERITY_RANK
BLOCK_THRESHOLD = {"none": 99, "critical": 4, "high": 3, "medium": 2}
AI_POLICY_RANK = {"allowed": 0, "restricted": 1, "forbidden": 2}
MODE_RANK = {"observe": 0, "enforce": 1}


class GovernanceError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _now() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- Politicas ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class EffectivePolicy:
    id: str | None
    name: str
    ai_policy: str
    required_reviews: int
    block_on_severity: str
    mode: str


DEFAULT_POLICY = EffectivePolicy(None, "Base (sin politica definida)", "allowed", 0, "high", "observe")


def _prefixes(text: str) -> list[str]:
    return [p.strip().lstrip("./") for p in text.replace("\n", ",").split(",") if p.strip()]


def policy_applies(policy: GovernancePolicy, repo_target_id: str, files: list[str]) -> bool:
    if not policy.is_active:
        return False
    if policy.repo_target_id and policy.repo_target_id != repo_target_id:
        return False
    prefixes = _prefixes(policy.path_prefixes)
    if not prefixes:
        return True
    return any(f.lstrip("./").startswith(p) for f in files for p in prefixes)


def _strictness(p: GovernancePolicy) -> tuple:
    return (AI_POLICY_RANK.get(p.ai_policy, 0), p.required_reviews, 100 - BLOCK_THRESHOLD.get(p.block_on_severity, 99),
            MODE_RANK.get(p.mode, 0))


def resolve_policy(policies: list[GovernancePolicy], repo_target_id: str, files: list[str]) -> EffectivePolicy:
    """La politica mas estricta de las que aplican (por repo y zona). Sin ninguna: la base (observar)."""
    candidates = [p for p in policies if policy_applies(p, repo_target_id, files)]
    if not candidates:
        return DEFAULT_POLICY
    best = max(candidates, key=_strictness)
    return EffectivePolicy(best.id, best.name, best.ai_policy, best.required_reviews, best.block_on_severity, best.mode)


def evaluate_change(origin: str, findings: list[dict], review_status: str, approvals: int,
                    policy: EffectivePolicy) -> tuple[str, list[dict]]:
    """(estado, violaciones). Estados: passed | blocked | observed_fail (hubiera bloqueado, pero la
    politica esta en modo "observar")."""
    violations: list[dict] = []
    is_ai = origin in AI_ORIGINS
    if is_ai and policy.ai_policy == "forbidden":
        violations.append({"code": "ai_forbidden", "message": "Esta zona no permite codigo escrito con IA."})
    threshold = BLOCK_THRESHOLD.get(policy.block_on_severity, 99)
    over = [f for f in findings if SEV_RANK.get(f.get("severity", ""), 0) >= threshold]
    if over:
        worst = max(over, key=lambda f: SEV_RANK.get(f.get("severity", ""), 0))
        violations.append({
            "code": "findings_over_threshold",
            "message": f"{len(over)} hallazgo(s) de severidad {policy.block_on_severity} o mayor "
                       f"(el peor: {worst.get('description') or worst.get('rule_id')}).",
        })
    needed = policy.required_reviews
    if is_ai and policy.ai_policy == "restricted":
        needed = max(needed, 1)
    if is_ai and needed > approvals:
        violations.append({
            "code": "missing_review",
            "message": f"Falta revision humana: {approvals} de {needed} aprobacion(es).",
        })
    if review_status == "rejected":
        violations.append({"code": "review_rejected", "message": "Una persona rechazo este cambio en la revision."})
    if not violations:
        return "passed", []
    return ("blocked" if policy.mode == "enforce" else "observed_fail"), violations


# --- Compuerta -------------------------------------------------------------------------------

def _approvals(change: CodeChange) -> int:
    return len(set(provenance.loads_list(change.reviewers_json)))


async def load_policies(db: AsyncSession, organization_id: str | None) -> list[GovernancePolicy]:
    result = await db.execute(select(GovernancePolicy).where(GovernancePolicy.organization_id == organization_id))
    return list(result.scalars().all())


async def apply_gate(db: AsyncSession, change: CodeChange, policies: list[GovernancePolicy], trigger: str,
                     actor: str = "sistema", record: bool = True) -> dict:
    """Evalua la compuerta para un cambio, actualiza su estado y deja constancia. `record=False` la
    usa la ingesta para no duplicar: el cambio ya queda registrado con su resultado."""
    files = provenance.loads_list(change.files_json)
    findings = provenance.loads_list(change.findings_json)
    policy = resolve_policy(policies, change.repo_target_id, files)
    status, violations = evaluate_change(change.origin, findings, change.review_status, _approvals(change), policy)
    previous = change.gate_status
    change.gate_status = status
    change.gate_policy_name = policy.name[:255]
    db.add(GateRun(
        organization_id=change.organization_id, repo_target_id=change.repo_target_id, change_id=change.id,
        commit_sha=change.commit_sha, status=status, mode=policy.mode, policy_name=policy.name[:255],
        violations_json=provenance.dumps(violations), trigger=trigger,
    ))
    if record:
        await ledger.append_entry(db, change.organization_id, "gate.evaluated", actor, change.commit_sha, {
            "repo_target_id": change.repo_target_id, "status": status, "previous_status": previous,
            "mode": policy.mode, "policy": policy.name, "trigger": trigger,
            "violations": [v["code"] for v in violations],
        })
    return {
        "allowed": status != "blocked", "status": status, "mode": policy.mode, "policy": policy.name,
        "policy_id": policy.id, "violations": violations, "change_id": change.id, "commit_sha": change.commit_sha,
    }


# --- Ingesta desde el historial de git ----------------------------------------------------------

async def _git_output(repo_dir: str, args: list[str], max_bytes: int | None = None) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
    proc = await asyncio.create_subprocess_exec(
        "git", "-C", repo_dir, "-c", "core.fsmonitor=false", *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=env,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError("timeout leyendo el historial de git")
    data = stdout[:max_bytes] if max_bytes else stdout
    return data.decode(errors="replace")


def _secret_findings_by_commit(secret_items: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for item in secret_items:
        sha = (item.get("commit_hash") or "").strip()
        if not sha:
            continue
        severity = item.get("severity")
        severity = getattr(severity, "value", severity) or "medium"
        out[sha].append({
            "source": "gitleaks", "rule_id": item.get("rule_id", ""), "severity": str(severity),
            "description": (item.get("description") or "Secreto detectado")[:200],
            "file": (item.get("file_path") or "")[:300], "line": item.get("start_line"),
            "snippet": item.get("match_redacted", ""),
        })
    return out


def _secrets_for(sha: str, by_commit: dict[str, list[dict]]) -> list[dict]:
    found: list[dict] = []
    for key, items in by_commit.items():
        if sha.startswith(key) or key.startswith(sha):
            found.extend(items)
    return found


def _merge_findings(current: list[dict], new: list[dict]) -> tuple[list[dict], int]:
    seen = {(f.get("source"), f.get("rule_id"), f.get("file"), f.get("line")) for f in current}
    merged = list(current)
    added = 0
    for f in new:
        key = (f.get("source"), f.get("rule_id"), f.get("file"), f.get("line"))
        if key not in seen and len(merged) < provenance.MAX_FINDINGS_PER_CHANGE:
            merged.append(f)
            seen.add(key)
            added += 1
    return merged, added


def _sev_counts(findings: list[dict]) -> dict:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f.get("severity", "low")] += 1
    return dict(counts)


async def ingest_history(db: AsyncSession, target: RepoTarget, repo_dir: str, secret_items: list[dict],
                         git=_git_output) -> dict:
    """Registra en el contador los commits NUEVOS del repositorio (los ya vistos no se tocan), revisa
    sus lineas agregadas, calcula la procedencia y evalua la compuerta. Tambien suma al cambio
    correspondiente los secretos que gitleaks encontro en commits ya registrados."""
    org = target.organization_id
    policies = await load_policies(db, org)
    existing_rows = (await db.execute(
        select(CodeChange).where(CodeChange.organization_id == org, CodeChange.repo_target_id == target.id)
    )).scalars().all()
    existing = {c.commit_sha: c for c in existing_rows}

    raw = await git(repo_dir, [*provenance.GIT_LOG_ARGS, f"-n{MAX_NEW_COMMITS}"])
    commits = provenance.parse_git_log(raw)
    secrets_by_commit = _secret_findings_by_commit(secret_items)

    stats = {"new_changes": 0, "ai_changes": 0, "blocked": 0, "observed_fail": 0, "updated_changes": 0}
    for c in reversed([c for c in commits if c.sha not in existing]):  # mas viejo primero: el registro sigue el orden real
        prov = provenance.detect_provenance(c.message, c.author_name, c.author_email)
        findings: list[dict] = []
        try:
            diff = await git(repo_dir, ["show", "--format=", "-U0", "--no-color", "--no-ext-diff", c.sha], MAX_DIFF_BYTES)
            findings = provenance.scan_diff(diff)
        except Exception as exc:  # noqa: BLE001 -- un diff ilegible no frena el registro del cambio
            logger.warning("no se pudo leer el diff de un commit", extra={"sha": c.sha[:10], "error": str(exc)[:200]})
        findings, _ = _merge_findings(findings, _secrets_for(c.sha, secrets_by_commit))
        change = CodeChange(
            organization_id=org, repo_target_id=target.id, commit_sha=c.sha, author_name=c.author_name[:255],
            author_email=c.author_email[:255], committed_at=c.committed_at, message=provenance.first_line(c.message),
            origin=prov.origin, ai_tool=prov.ai_tool, ai_model=prov.ai_model, prompt_ref=prov.prompt_ref,
            detection=prov.detection, lines_added=c.lines_added, lines_removed=c.lines_removed,
            files_changed=len(c.files), files_json=provenance.dumps(c.files[:200]), findings_json=provenance.dumps(findings),
        )
        db.add(change)
        await db.flush()
        result = await apply_gate(db, change, policies, "scan", record=False)
        await ledger.append_entry(db, org, "change.recorded", "sistema", c.sha, {
            "repo": target.name, "repo_target_id": target.id, "author": c.author_email, "origin": prov.origin,
            "detection": prov.detection, "ai_tool": prov.ai_tool, "ai_model": prov.ai_model,
            "lines_added": c.lines_added, "lines_removed": c.lines_removed, "files": len(c.files),
            "findings": _sev_counts(findings), "gate": result["status"], "policy": result["policy"],
        })
        stats["new_changes"] += 1
        stats["ai_changes"] += 1 if prov.origin in AI_ORIGINS else 0
        stats["blocked"] += 1 if result["status"] == "blocked" else 0
        stats["observed_fail"] += 1 if result["status"] == "observed_fail" else 0

    # Secretos nuevos en commits que ya estaban registrados.
    for sha, change in existing.items():
        extra = _secrets_for(sha, secrets_by_commit)
        if not extra:
            continue
        merged, added = _merge_findings(provenance.loads_list(change.findings_json), extra)
        if added:
            change.findings_json = provenance.dumps(merged)
            await ledger.append_entry(db, org, "change.finding_added", "sistema", sha, {
                "repo_target_id": target.id, "added": added, "findings": _sev_counts(merged)})
            await apply_gate(db, change, policies, "scan")
            stats["updated_changes"] += 1

    await ledger.append_entry(db, org, "scan.ingested", "sistema", target.id, {
        "repo": target.name, "commits_seen": len(commits), **stats})
    await db.flush()
    return stats


# --- Declarar origen y revisar -----------------------------------------------------------------

async def declare_origin(db: AsyncSession, change: CodeChange, origin: str, ai_tool: str, ai_model: str,
                         prompt_ref: str, actor: str) -> dict:
    if origin not in provenance.VALID_ORIGINS:
        raise GovernanceError("origin debe ser human, ai o mixed", 422)
    before = {"origin": change.origin, "ai_tool": change.ai_tool, "ai_model": change.ai_model, "prompt_ref": change.prompt_ref}
    change.origin = origin
    change.ai_tool = (ai_tool or "")[:100] if origin != "human" else ""
    change.ai_model = (ai_model or "")[:150] if origin != "human" else ""
    change.prompt_ref = (prompt_ref or "")[:500] if origin != "human" else ""
    change.detection = "declared"
    after = {"origin": change.origin, "ai_tool": change.ai_tool, "ai_model": change.ai_model, "prompt_ref": change.prompt_ref}
    await ledger.append_entry(db, change.organization_id, "change.origin_declared", actor, change.commit_sha,
                              {"repo_target_id": change.repo_target_id, "before": before, "after": after})
    policies = await load_policies(db, change.organization_id)
    return await apply_gate(db, change, policies, "manual", actor)


async def review_change(db: AsyncSession, change: CodeChange, decision: str, comment: str, reviewer_email: str) -> dict:
    if decision not in ("approve", "reject"):
        raise GovernanceError("decision debe ser approve o reject", 422)
    policies = await load_policies(db, change.organization_id)
    policy = resolve_policy(policies, change.repo_target_id, provenance.loads_list(change.files_json))
    reviewer = (reviewer_email or "").strip().lower()
    is_self = bool(reviewer) and reviewer == (change.author_email or "").strip().lower()
    if decision == "approve" and is_self and policy.mode == "enforce":
        raise GovernanceError("No podes aprobar tu propio cambio: lo tiene que revisar otra persona.", 403)
    reviewers = provenance.loads_list(change.reviewers_json)
    if decision == "approve":
        if reviewer not in reviewers:
            reviewers.append(reviewer)
        change.reviewers_json = provenance.dumps(reviewers)
        change.review_status = "approved"
    else:
        change.review_status = "rejected"
    change.review_count = len(set(reviewers))
    change.reviewed_by = reviewer[:255]
    change.reviewed_at = _now()
    await ledger.append_entry(db, change.organization_id, "change.reviewed", reviewer, change.commit_sha, {
        "repo_target_id": change.repo_target_id, "decision": decision, "comment": (comment or "")[:500],
        "self_review": is_self, "approvals": change.review_count,
    })
    return await apply_gate(db, change, policies, "review", reviewer)


# --- CI: evaluar un cambio que todavia no se integro ----------------------------------------------

async def evaluate_external(db: AsyncSession, target: RepoTarget, data: dict, actor: str) -> dict:
    """Usado por el pipeline de CI antes de integrar: crea (o reutiliza) el cambio del commit, suma los
    hallazgos del diff que mande el pipeline y devuelve si se puede integrar."""
    sha = (data.get("commit_sha") or "").strip()
    if not sha:
        raise GovernanceError("commit_sha es obligatorio", 422)
    org = target.organization_id
    change = (await db.execute(select(CodeChange).where(
        CodeChange.organization_id == org, CodeChange.repo_target_id == target.id, CodeChange.commit_sha == sha
    ))).scalars().first()
    diff_findings = provenance.scan_diff(data["diff"]) if data.get("diff") else []
    given = [dict(f, source="ci") for f in (data.get("findings") or [])]
    files = list(data.get("files") or [])[:200]
    if change is None:
        added = sum(1 for _ in provenance.parse_diff_added_lines(data["diff"])) if data.get("diff") else 0
        message = data.get("message") or ""
        prov = provenance.detect_provenance(message, data.get("author_name", ""), data.get("author_email", ""))
        if data.get("origin") in provenance.VALID_ORIGINS:
            prov = provenance.Provenance(
                data["origin"], data.get("ai_tool", ""), data.get("ai_model", ""), data.get("prompt_ref", ""), "declared")
        findings, _ = _merge_findings(diff_findings, given)
        change = CodeChange(
            organization_id=org, repo_target_id=target.id, commit_sha=sha[:64],
            author_name=(data.get("author_name") or "")[:255], author_email=(data.get("author_email") or "")[:255],
            committed_at=_now(), message=provenance.first_line(message), origin=prov.origin, ai_tool=prov.ai_tool,
            ai_model=prov.ai_model, prompt_ref=prov.prompt_ref, detection=prov.detection,
            lines_added=int(data.get("lines_added") or added), lines_removed=int(data.get("lines_removed") or 0),
            files_changed=len(files), files_json=provenance.dumps(files), findings_json=provenance.dumps(findings),
        )
        db.add(change)
        await db.flush()
        await ledger.append_entry(db, org, "change.recorded", actor, sha, {
            "repo": target.name, "repo_target_id": target.id, "origin": change.origin, "detection": change.detection,
            "ai_tool": change.ai_tool, "ai_model": change.ai_model, "lines_added": change.lines_added,
            "files": change.files_changed, "findings": _sev_counts(findings), "via": "ci"})
    else:
        merged, added = _merge_findings(provenance.loads_list(change.findings_json), diff_findings + given)
        if added:
            change.findings_json = provenance.dumps(merged)
        if data.get("origin") in provenance.VALID_ORIGINS and data["origin"] != change.origin:
            await declare_origin(db, change, data["origin"], data.get("ai_tool", ""), data.get("ai_model", ""),
                                 data.get("prompt_ref", ""), actor)
    policies = await load_policies(db, org)
    return await apply_gate(db, change, policies, "ci", actor)


# --- Politicas (CRUD con registro) -------------------------------------------------------------

def policy_snapshot(p: GovernancePolicy) -> dict:
    return {"id": p.id, "name": p.name, "repo_target_id": p.repo_target_id, "path_prefixes": p.path_prefixes,
            "ai_policy": p.ai_policy, "required_reviews": p.required_reviews, "block_on_severity": p.block_on_severity,
            "mode": p.mode, "is_active": p.is_active}


# --- Metricas ------------------------------------------------------------------------------------

def _week_key(dt: datetime) -> str:
    return (dt - timedelta(days=dt.weekday())).date().isoformat()


async def compute_metrics(db: AsyncSession, organization_id: str | None, days: int = 30,
                          hours_per_ai_change: float = 0.0) -> dict:
    since = _now() - timedelta(days=days)
    rows = (await db.execute(
        select(CodeChange).where(CodeChange.organization_id == organization_id, CodeChange.committed_at >= since)
        .limit(50000)
    )).scalars().all()
    repos = {t.id: t.name for t in (await db.execute(
        select(RepoTarget).where(RepoTarget.organization_id == organization_id))).scalars().all()}

    def is_ai(c: CodeChange) -> bool:
        return c.origin in AI_ORIGINS

    totals = {"changes": len(rows), "human": 0, "ai": 0, "mixed": 0, "lines_added": 0, "ai_lines": 0, "human_lines": 0}
    gate = {"passed": 0, "blocked": 0, "observed_fail": 0}
    sev_ai: dict[str, int] = defaultdict(int)
    sev_human: dict[str, int] = defaultdict(int)
    findings_ai = findings_human = 0
    review_needed = review_done = 0
    review_hours: list[float] = []
    per_repo: dict[str, dict] = {}
    weekly: dict[str, dict] = {}
    tools: dict[str, int] = defaultdict(int)

    for c in rows:
        totals[c.origin if c.origin in ("human", "ai", "mixed") else "human"] += 1
        totals["lines_added"] += c.lines_added
        findings = provenance.loads_list(c.findings_json)
        if is_ai(c):
            totals["ai_lines"] += c.lines_added
            findings_ai += len(findings)
            for f in findings:
                sev_ai[f.get("severity", "low")] += 1
            review_needed += 1
            if c.review_status == "approved":
                review_done += 1
            if c.ai_tool:
                tools[c.ai_tool] += 1
        else:
            totals["human_lines"] += c.lines_added
            findings_human += len(findings)
            for f in findings:
                sev_human[f.get("severity", "low")] += 1
        gate[c.gate_status if c.gate_status in gate else "passed"] += 1
        reviewed_at, committed_at = aware(c.reviewed_at), aware(c.committed_at)
        if reviewed_at and committed_at:
            review_hours.append(max(0.0, (reviewed_at - committed_at).total_seconds() / 3600))
        repo = per_repo.setdefault(c.repo_target_id, {
            "repo_target_id": c.repo_target_id, "repo": repos.get(c.repo_target_id, "(repositorio eliminado)"),
            "changes": 0, "ai_changes": 0, "lines_added": 0, "ai_lines": 0, "findings": 0, "blocked": 0})
        repo["changes"] += 1
        repo["lines_added"] += c.lines_added
        repo["findings"] += len(findings)
        repo["ai_changes"] += 1 if is_ai(c) else 0
        repo["ai_lines"] += c.lines_added if is_ai(c) else 0
        repo["blocked"] += 1 if c.gate_status in ("blocked", "observed_fail") else 0
        wk = weekly.setdefault(_week_key(aware(c.committed_at)), {
            "week": _week_key(aware(c.committed_at)), "human_lines": 0, "ai_lines": 0, "findings": 0, "flagged": 0})
        wk["ai_lines" if is_ai(c) else "human_lines"] += c.lines_added
        wk["findings"] += len(findings)
        wk["flagged"] += 1 if c.gate_status in ("blocked", "observed_fail") else 0

    ai_changes = totals["ai"] + totals["mixed"]

    def pct(part: float, whole: float) -> float:
        return round(100.0 * part / whole, 1) if whole else 0.0

    def per_kloc(findings: int, lines: int) -> float:
        return round(findings / (lines / 1000.0), 2) if lines else 0.0

    ledger_info = await ledger.head(db, organization_id)
    for r in per_repo.values():
        r["ai_share_pct"] = pct(r["ai_changes"], r["changes"])
    return {
        "window_days": days,
        "totals": {**totals, "ai_changes": ai_changes, "ai_share_pct": pct(ai_changes, totals["changes"]),
                   "ai_lines_share_pct": pct(totals["ai_lines"], totals["lines_added"])},
        "review": {"ai_changes_needing_review": review_needed, "ai_changes_approved": review_done,
                   "coverage_pct": pct(review_done, review_needed),
                   "avg_review_hours": round(sum(review_hours) / len(review_hours), 1) if review_hours else None},
        "gate": gate,
        "findings": {
            "in_ai_code": findings_ai, "in_human_code": findings_human,
            "per_1000_lines_ai": per_kloc(findings_ai, totals["ai_lines"]),
            "per_1000_lines_human": per_kloc(findings_human, totals["human_lines"]),
            "severity_ai": dict(sev_ai), "severity_human": dict(sev_human),
        },
        "roi": {
            "hours_per_ai_change": hours_per_ai_change,
            "estimated_hours_saved": round(ai_changes * hours_per_ai_change, 1) if hours_per_ai_change else None,
            "note": "Estimacion: cambios con IA x horas que la empresa asigna a cada uno. No se mide automaticamente.",
        },
        "tools": [{"tool": k, "changes": v} for k, v in sorted(tools.items(), key=lambda kv: -kv[1])],
        "by_repo": sorted(per_repo.values(), key=lambda r: -r["changes"]),
        "weekly": sorted(weekly.values(), key=lambda w: w["week"]),
        "ledger": {"entries": ledger_info["entries"], "head_hash": ledger_info["head_hash"]},
    }
