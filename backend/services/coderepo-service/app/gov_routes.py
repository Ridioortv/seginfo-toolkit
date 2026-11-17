"""Endpoints de la app "Gobernanza de codigo con IA" (se montan bajo /governance en app/main.py)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db
from backend.shared.tenancy import org_id_from_claims
from app import governance, ledger, provenance, services
from app.dependencies import get_current_claims, require_role
from app.gov_models import CodeChange, GateRun, GovernancePolicy
from app.gov_schemas import (
    AnchorOut, ChangeOut, ChangePage, FindingOut, GateEvaluateIn, GateResult, GateRunOut, LedgerEntryOut, LedgerPage,
    OriginDeclaration, PolicyIn, PolicyOut, ReviewIn, VerifyOut,
)
from app.models import RepoTarget

router = APIRouter(prefix="/governance", tags=["governance"])

WRITERS = ("admin", "soc_manager", "analyst")
POLICY_ADMINS = ("admin", "soc_manager")


def _actor(claims: dict) -> str:
    return claims.get("email") or claims.get("sub", "")


async def _repo_names(db: AsyncSession, org: str | None) -> dict[str, str]:
    rows = (await db.execute(select(RepoTarget).where(RepoTarget.organization_id == org))).scalars().all()
    return {r.id: r.name for r in rows}


def _change_out(c: CodeChange, names: dict[str, str]) -> ChangeOut:
    return ChangeOut(
        id=c.id, repo_target_id=c.repo_target_id, repo_name=names.get(c.repo_target_id, ""), commit_sha=c.commit_sha,
        author_name=c.author_name, author_email=c.author_email, committed_at=c.committed_at, message=c.message,
        origin=c.origin, ai_tool=c.ai_tool, ai_model=c.ai_model, prompt_ref=c.prompt_ref, detection=c.detection,
        lines_added=c.lines_added, lines_removed=c.lines_removed, files_changed=c.files_changed,
        files=provenance.loads_list(c.files_json)[:200],
        findings=[FindingOut(**{k: v for k, v in f.items() if k in FindingOut.model_fields})
                  for f in provenance.loads_list(c.findings_json)],
        review_status=c.review_status, review_count=c.review_count, reviewed_by=c.reviewed_by,
        reviewed_at=c.reviewed_at, gate_status=c.gate_status, gate_policy_name=c.gate_policy_name,
    )


async def _get_change(db: AsyncSession, change_id: str, org: str | None) -> CodeChange:
    change = await db.get(CodeChange, change_id)
    if change is None or change.organization_id != org:
        raise HTTPException(status_code=404, detail="Cambio no encontrado")
    return change


def _gov_error(exc: governance.GovernanceError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.message)


# --- 1. Procedencia ----------------------------------------------------------------------------

@router.get("/changes", response_model=ChangePage)
async def list_changes(
    repo_target_id: str | None = None, origin: str | None = None, gate_status: str | None = None,
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    org = org_id_from_claims(claims)
    conds = [CodeChange.organization_id == org]
    if repo_target_id:
        conds.append(CodeChange.repo_target_id == repo_target_id)
    if origin:
        conds.append(CodeChange.origin == origin)
    if gate_status:
        conds.append(CodeChange.gate_status == gate_status)
    total = (await db.execute(select(func.count()).select_from(CodeChange).where(*conds))).scalar_one()
    rows = (await db.execute(
        select(CodeChange).where(*conds).order_by(CodeChange.committed_at.desc()).limit(limit).offset(offset)
    )).scalars().all()
    names = await _repo_names(db, org)
    return ChangePage(total=total, items=[_change_out(c, names) for c in rows])


@router.get("/changes/{change_id}", response_model=ChangeOut)
async def get_change(change_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    return _change_out(await _get_change(db, change_id, org), await _repo_names(db, org))


@router.patch("/changes/{change_id}", response_model=GateResult)
async def declare_origin(
    change_id: str, payload: OriginDeclaration,
    claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db),
):
    """Declarar o corregir el origen de un cambio (queda en el registro con el antes y el despues)."""
    change = await _get_change(db, change_id, org_id_from_claims(claims))
    try:
        result = await governance.declare_origin(
            db, change, payload.origin, payload.ai_tool, payload.ai_model, payload.prompt_ref, _actor(claims))
    except governance.GovernanceError as exc:
        raise _gov_error(exc)
    await db.commit()
    return result


@router.post("/changes/{change_id}/review", response_model=GateResult)
async def review_change(
    change_id: str, payload: ReviewIn,
    claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db),
):
    change = await _get_change(db, change_id, org_id_from_claims(claims))
    try:
        result = await governance.review_change(db, change, payload.decision, payload.comment, _actor(claims))
    except governance.GovernanceError as exc:
        raise _gov_error(exc)
    await db.commit()
    return result


# --- 2. Compuerta -------------------------------------------------------------------------------

def _same_repo(a: str, b: str) -> bool:
    def norm(u: str) -> str:
        u = services.strip_repo_url_userinfo(u).strip().lower().rstrip("/")
        return u[:-4] if u.endswith(".git") else u
    return norm(a) == norm(b)


@router.post("/gate/evaluate", response_model=GateResult)
async def gate_evaluate(
    payload: GateEvaluateIn, claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db),
):
    """Para el pipeline de CI: antes de integrar un cambio, consulta si pasa la compuerta. Si la politica
    esta en modo "exigir" y no pasa, `allowed` es false y el pipeline tiene que cortar."""
    org = org_id_from_claims(claims)
    target = None
    if payload.repo_target_id:
        target = await services.get_target(db, payload.repo_target_id, org)
    elif payload.repo_url:
        for t in await services.list_targets(db, org):
            if _same_repo(t.repo_url, payload.repo_url):
                target = t
                break
    if target is None:
        raise HTTPException(status_code=404, detail="Repositorio no encontrado (conectalo primero en Codigo y Repositorios)")
    try:
        result = await governance.evaluate_external(db, target, payload.model_dump(), _actor(claims))
    except governance.GovernanceError as exc:
        raise _gov_error(exc)
    await db.commit()
    return result


@router.get("/gate/runs", response_model=list[GateRunOut])
async def gate_runs(
    limit: int = Query(50, ge=1, le=200), status: str | None = None,
    claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    org = org_id_from_claims(claims)
    q = select(GateRun).where(GateRun.organization_id == org)
    if status:
        q = q.where(GateRun.status == status)
    rows = (await db.execute(q.order_by(GateRun.created_at.desc()).limit(limit))).scalars().all()
    names = await _repo_names(db, org)
    return [GateRunOut(
        id=r.id, repo_target_id=r.repo_target_id, repo_name=names.get(r.repo_target_id, ""), change_id=r.change_id,
        commit_sha=r.commit_sha, status=r.status, mode=r.mode, policy_name=r.policy_name,
        violations=provenance.loads_list(r.violations_json), trigger=r.trigger, created_at=r.created_at,
    ) for r in rows]


# --- 4. Politicas --------------------------------------------------------------------------------

async def _policy_out(db: AsyncSession, p: GovernancePolicy, names: dict[str, str] | None = None) -> PolicyOut:
    names = names if names is not None else await _repo_names(db, p.organization_id)
    return PolicyOut(
        id=p.id, name=p.name, repo_target_id=p.repo_target_id, repo_name=names.get(p.repo_target_id or "", ""),
        path_prefixes=p.path_prefixes, ai_policy=p.ai_policy, required_reviews=p.required_reviews,
        block_on_severity=p.block_on_severity, mode=p.mode, is_active=p.is_active, created_by=p.created_by,
        updated_by=p.updated_by, created_at=p.created_at, updated_at=p.updated_at,
    )


async def _check_policy_repo(db: AsyncSession, payload: PolicyIn, org: str | None) -> None:
    if payload.repo_target_id and await services.get_target(db, payload.repo_target_id, org) is None:
        raise HTTPException(status_code=404, detail="Repositorio no encontrado")


@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    names = await _repo_names(db, org)
    rows = (await db.execute(
        select(GovernancePolicy).where(GovernancePolicy.organization_id == org).order_by(GovernancePolicy.name))).scalars().all()
    return [await _policy_out(db, p, names) for p in rows]


@router.post("/policies", response_model=PolicyOut, status_code=201)
async def create_policy(
    payload: PolicyIn, claims: dict = Depends(require_role(*POLICY_ADMINS)), db: AsyncSession = Depends(get_db),
):
    org = org_id_from_claims(claims)
    await _check_policy_repo(db, payload, org)
    p = GovernancePolicy(organization_id=org, created_by=_actor(claims), updated_by=_actor(claims), **payload.model_dump())
    db.add(p)
    await db.flush()
    await ledger.append_entry(db, org, "policy.created", _actor(claims), p.id, governance.policy_snapshot(p))
    await db.commit()
    return await _policy_out(db, p)


@router.put("/policies/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: str, payload: PolicyIn,
    claims: dict = Depends(require_role(*POLICY_ADMINS)), db: AsyncSession = Depends(get_db),
):
    org = org_id_from_claims(claims)
    p = await db.get(GovernancePolicy, policy_id)
    if p is None or p.organization_id != org:
        raise HTTPException(status_code=404, detail="Politica no encontrada")
    await _check_policy_repo(db, payload, org)
    before = governance.policy_snapshot(p)
    for key, value in payload.model_dump().items():
        setattr(p, key, value)
    p.updated_by = _actor(claims)
    p.updated_at = datetime.now(timezone.utc)
    await ledger.append_entry(db, org, "policy.updated", _actor(claims), p.id,
                              {"before": before, "after": governance.policy_snapshot(p)})
    await db.commit()
    return await _policy_out(db, p)


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str, claims: dict = Depends(require_role(*POLICY_ADMINS)), db: AsyncSession = Depends(get_db),
):
    org = org_id_from_claims(claims)
    p = await db.get(GovernancePolicy, policy_id)
    if p is None or p.organization_id != org:
        raise HTTPException(status_code=404, detail="Politica no encontrada")
    await ledger.append_entry(db, org, "policy.deleted", _actor(claims), p.id, governance.policy_snapshot(p))
    await db.delete(p)
    await db.commit()


# --- 5. Metricas ---------------------------------------------------------------------------------

@router.get("/metrics")
async def metrics(
    days: int = Query(30, ge=1, le=365), hours_per_ai_change: float = Query(0.0, ge=0, le=1000),
    claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    return await governance.compute_metrics(db, org_id_from_claims(claims), days, hours_per_ai_change)


# --- 3. Registro auditable ---------------------------------------------------------------------

@router.get("/ledger", response_model=LedgerPage)
async def get_ledger(
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), event_type: str | None = None,
    claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    total, rows = await ledger.list_entries(db, org_id_from_claims(claims), limit, offset, event_type)
    return LedgerPage(total=total, items=[LedgerEntryOut(**ledger.entry_to_dict(e)) for e in rows])


@router.get("/ledger/verify", response_model=VerifyOut)
async def verify_ledger(
    expected_count: int | None = Query(None, ge=0), expected_head: str | None = Query(None, max_length=64),
    claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    """Recalcula toda la cadena. Con un ancla guardada por fuera (expected_count/expected_head) tambien
    detecta que se hayan borrado entradas del final."""
    return await ledger.verify_chain(db, org_id_from_claims(claims), expected_count, expected_head)


@router.get("/ledger/anchor", response_model=AnchorOut)
async def ledger_anchor(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await ledger.anchor(db, org_id_from_claims(claims))


@router.get("/ledger/export")
async def export_ledger(
    format: str = Query("json", pattern="^(json|csv)$"),
    claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    org = org_id_from_claims(claims)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if format == "csv":
        body = await ledger.export_csv(db, org)
        return Response(body, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="tero-registro-{stamp}.csv"'})
    import json
    body = json.dumps(await ledger.export_json(db, org), indent=2, ensure_ascii=False)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="tero-registro-{stamp}.json"'})
