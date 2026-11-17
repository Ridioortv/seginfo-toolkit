"""API del riesgo de proveedores (case-service).

  * Leen admin, soc_manager y analyst; crean, cambian, mandan cuestionarios y firman admin y soc_manager.
  * Las rutas /public/vendor-assessments/{token} NO llevan login a proposito: las usa el proveedor desde el link que le
    mandaron. Se protegen con un token al azar de 256 bits (solo se guarda su hash), vencimiento, un solo uso y limite de
    intentos por IP y por token."""
import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db
from backend.shared.rate_limit import check_rate_limit
from backend.shared.tenancy import org_id_from_claims
from app import vendor_catalog as cat
from app import vendor_service as svc
from app.dependencies import require_role

router = APIRouter()
public_router = APIRouter()
READERS = ("admin", "soc_manager", "analyst")
WRITERS = ("admin", "soc_manager")

Criticality = Literal["critical", "high", "medium", "low"]


def _aware(v):
    if isinstance(v, datetime) and v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v


class VendorIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    domain: str = Field(default="", max_length=300)
    criticality: Criticality = "medium"
    service_description: str = Field(default="", max_length=2000)
    data_types: list[str] = Field(default_factory=list, max_length=10)
    owner: str = Field(default="", max_length=255)
    contact_email: str = Field(default="", max_length=255)
    contract_end: datetime | None = None
    notes: str = Field(default="", max_length=2000)

    _tz = field_validator("contract_end")(lambda cls, v: _aware(v))


class VendorPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    domain: str | None = Field(default=None, max_length=300)
    criticality: Criticality | None = None
    service_description: str | None = Field(default=None, max_length=2000)
    data_types: list[str] | None = Field(default=None, max_length=10)
    owner: str | None = Field(default=None, max_length=255)
    contact_email: str | None = Field(default=None, max_length=255)
    contract_end: datetime | None = None
    notes: str | None = Field(default=None, max_length=2000)
    status: Literal["active", "offboarded"] | None = None

    _tz = field_validator("contract_end")(lambda cls, v: _aware(v))


class AssessmentIn(BaseModel):
    days: int = Field(default=cat.DEFAULT_LINK_DAYS, ge=1, le=90)


class EvidenceIn(BaseModel):
    kind: Literal["iso27001", "soc2", "pentest", "dpa", "bcp", "insurance", "other"]
    title: str = Field(min_length=3, max_length=255)
    issued_at: datetime | None = None
    valid_until: datetime | None = None
    reference_url: str = Field(default="", max_length=500)
    document_sha256: str = Field(default="", max_length=64)
    note: str = Field(default="", max_length=1000)

    _tz = field_validator("issued_at", "valid_until")(lambda cls, v: _aware(v))


class PublicSubmit(BaseModel):
    respondent_name: str = Field(min_length=2, max_length=255)
    respondent_email: str = Field(min_length=5, max_length=255)
    answers: dict = Field(default_factory=dict)


def _actor(claims: dict) -> str:
    return claims.get("email") or claims.get("sub", "")


def _fail(exc: svc.VendorError):
    raise HTTPException(status_code=exc.status, detail=str(exc))


async def _vendor_or_404(db: AsyncSession, claims: dict, vendor_id: str):
    vendor = await svc.get_vendor(db, org_id_from_claims(claims), vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Proveedor no encontrado")
    return vendor


# ----------------------------- panel (con login) -----------------------------

@router.get("/vendors/questionnaire")
async def vendor_questionnaire(claims: dict = Depends(require_role(*READERS))):
    return {"template": cat.TEMPLATE_VERSION, "questions": cat.QUESTIONS, "evidence_kinds": cat.EVIDENCE_LABEL,
            "data_types": list(cat.DATA_TYPES)}


@router.get("/vendors/summary")
async def vendor_summary(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    return svc.summarize(await svc.list_views(db, org_id_from_claims(claims)))


@router.get("/vendors/report.csv")
async def vendor_report_csv(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    views = await svc.list_views(db, org_id_from_claims(claims), include_offboarded=True)
    return Response(content=svc.report_csv(views), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="riesgo-proveedores.csv"'})


@router.get("/vendors/attestation")
async def vendor_attestation(claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db)):
    doc = await svc.make_attestation(db, org_id_from_claims(claims), _actor(claims))
    await db.commit()
    return Response(content=json.dumps(doc, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="atestado-proveedores.json"'})


@router.get("/vendors")
async def vendor_list(include_offboarded: bool = False, claims: dict = Depends(require_role(*READERS)),
                      db: AsyncSession = Depends(get_db)):
    return await svc.list_views(db, org_id_from_claims(claims), include_offboarded)


@router.post("/vendors", status_code=201)
async def vendor_create(payload: VendorIn, claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    try:
        vendor = await svc.create_vendor(db, org, _actor(claims), payload.model_dump())
    except svc.VendorError as exc:
        _fail(exc)
    await db.commit()
    return await svc.detail_view(db, org, vendor)


@router.get("/vendors/{vendor_id}")
async def vendor_detail(vendor_id: str, claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    vendor = await _vendor_or_404(db, claims, vendor_id)
    return await svc.detail_view(db, org_id_from_claims(claims), vendor)


@router.patch("/vendors/{vendor_id}")
async def vendor_update(vendor_id: str, payload: VendorPatch, claims: dict = Depends(require_role(*WRITERS)),
                        db: AsyncSession = Depends(get_db)):
    vendor = await _vendor_or_404(db, claims, vendor_id)
    org = org_id_from_claims(claims)
    try:
        await svc.update_vendor(db, org, _actor(claims), vendor, payload.model_dump(exclude_unset=True))
    except svc.VendorError as exc:
        _fail(exc)
    await db.commit()
    return await svc.detail_view(db, org, vendor)


@router.post("/vendors/{vendor_id}/assessments", status_code=201)
async def vendor_send_assessment(vendor_id: str, payload: AssessmentIn, claims: dict = Depends(require_role(*WRITERS)),
                                 db: AsyncSession = Depends(get_db)):
    """Crea el cuestionario y devuelve el token UNA sola vez: despues solo queda su hash. El frontend arma el link
    (/proveedor/<token>) con el origen desde el que se usa TERO."""
    vendor = await _vendor_or_404(db, claims, vendor_id)
    try:
        row, token = await svc.create_assessment(db, org_id_from_claims(claims), _actor(claims), vendor, payload.days)
    except svc.VendorError as exc:
        _fail(exc)
    await db.commit()
    return {"id": row.id, "token": token, "path": f"/proveedor/{token}", "expires_at": row.expires_at.isoformat()}


@router.get("/vendors/{vendor_id}/assessments/{assessment_id}")
async def vendor_assessment_detail(vendor_id: str, assessment_id: str, claims: dict = Depends(require_role(*READERS)),
                                   db: AsyncSession = Depends(get_db)):
    await _vendor_or_404(db, claims, vendor_id)
    row = await svc.get_assessment(db, org_id_from_claims(claims), vendor_id, assessment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Cuestionario no encontrado")
    return svc.assessment_view(row, svc._now(), with_answers=True)


@router.post("/vendors/{vendor_id}/assessments/{assessment_id}/cancel", status_code=200)
async def vendor_cancel_assessment(vendor_id: str, assessment_id: str, claims: dict = Depends(require_role(*WRITERS)),
                                   db: AsyncSession = Depends(get_db)):
    vendor = await _vendor_or_404(db, claims, vendor_id)
    org = org_id_from_claims(claims)
    row = await svc.get_assessment(db, org, vendor_id, assessment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Cuestionario no encontrado")
    try:
        await svc.cancel_assessment(db, org, _actor(claims), vendor, row)
    except svc.VendorError as exc:
        _fail(exc)
    await db.commit()
    return {"id": row.id, "status": row.status}


@router.post("/vendors/{vendor_id}/evidence", status_code=201)
async def vendor_add_evidence(vendor_id: str, payload: EvidenceIn, claims: dict = Depends(require_role(*WRITERS)),
                              db: AsyncSession = Depends(get_db)):
    vendor = await _vendor_or_404(db, claims, vendor_id)
    try:
        row = await svc.add_evidence(db, org_id_from_claims(claims), _actor(claims), vendor, payload.model_dump())
    except svc.VendorError as exc:
        _fail(exc)
    await db.commit()
    return svc.evidence_view(row, svc._now())


@router.delete("/vendors/{vendor_id}/evidence/{evidence_id}", status_code=204)
async def vendor_remove_evidence(vendor_id: str, evidence_id: str, claims: dict = Depends(require_role(*WRITERS)),
                                 db: AsyncSession = Depends(get_db)):
    vendor = await _vendor_or_404(db, claims, vendor_id)
    if not await svc.remove_evidence(db, org_id_from_claims(claims), _actor(claims), vendor, evidence_id):
        raise HTTPException(status_code=404, detail="Evidencia no encontrada")
    await db.commit()
    return Response(status_code=204)


# ----------------------------- link publico del proveedor -----------------------------

def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "")) or "desconocida"


async def _limit(request: Request, token: str, action: str, per_ip: int, per_token: int) -> None:
    ok_ip = await check_rate_limit(f"vendor-{action}-ip:{_client_ip(request)}", per_ip, 3600)
    ok_tok = await check_rate_limit(f"vendor-{action}-tok:{token[:16]}", per_token, 3600)
    if not (ok_ip and ok_tok):
        raise HTTPException(status_code=429, detail="Demasiados intentos. Proba de nuevo en un rato.")


@public_router.get("/public/vendor-assessments/{token}")
async def public_assessment(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    await _limit(request, token, "view", 120, 120)
    row = await svc.find_by_token(db, token)
    if row is None:
        raise HTTPException(status_code=404, detail="Este link no existe o ya no es valido")
    state = svc.assessment_state(row)
    vendor = await svc.get_vendor(db, row.organization_id, row.vendor_id)
    return {"state": state, "vendor_name": vendor.name if vendor else "", "expires_at": svc._iso(row.expires_at),
            "questions": cat.public_questions() if state == "sent" else [], "answers_options": list(cat.ANSWERS)}


@public_router.post("/public/vendor-assessments/{token}", status_code=201)
async def public_submit(token: str, payload: PublicSubmit, request: Request, db: AsyncSession = Depends(get_db)):
    await _limit(request, token, "submit", 20, 20)
    row = await svc.find_by_token(db, token)
    if row is None:
        raise HTTPException(status_code=404, detail="Este link no existe o ya no es valido")
    try:
        await svc.submit_assessment(db, row, payload.respondent_name, payload.respondent_email, payload.answers)
    except svc.VendorError as exc:
        _fail(exc)
    await db.commit()
    return {"ok": True, "message": "Gracias. Recibimos tus respuestas."}
