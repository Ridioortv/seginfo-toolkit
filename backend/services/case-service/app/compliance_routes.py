"""API del cumplimiento con evidencia viva (case-service). Leen admin, soc_manager y analyst; declaran y generan
fotos o atestados admin y soc_manager."""
import json

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db
from backend.shared.tenancy import org_id_from_claims
from app import compliance_catalog as cat
from app import compliance_service as svc
from app.dependencies import require_role

router = APIRouter()
READERS = ("admin", "soc_manager", "analyst")
WRITERS = ("admin", "soc_manager")


class DeclarationIn(BaseModel):
    control_id: str = Field(min_length=3, max_length=20)
    answer: str = Field(pattern="^(yes|partial|no)$")
    note: str = Field(min_length=10, max_length=2000)
    valid_months: int = Field(default=svc.DEFAULT_VALID_MONTHS, ge=1, le=24)


def _actor(claims: dict) -> str:
    return claims.get("email") or claims.get("sub", "")


@router.get("/compliance/status")
async def compliance_status(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    ev = await svc.evaluate(db, org_id_from_claims(claims))
    ev["history"] = await svc.history(db, org_id_from_claims(claims))
    return ev


@router.post("/compliance/snapshot", status_code=201)
async def compliance_snapshot(claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db)):
    snap = await svc.make_snapshot(db, org_id_from_claims(claims), _actor(claims))
    await db.commit()
    return {"id": snap.id, "score_verified": snap.score_verified, "score_total": snap.score_total,
            "body_sha256": snap.body_sha256, "created_at": snap.created_at.isoformat()}


@router.post("/compliance/declarations", status_code=201)
async def compliance_declare(payload: DeclarationIn, claims: dict = Depends(require_role(*WRITERS)),
                             db: AsyncSession = Depends(get_db)):
    try:
        row = await svc.declare(db, org_id_from_claims(claims), _actor(claims), payload.control_id, payload.answer,
                                payload.note, payload.valid_months)
    except svc.ComplianceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await db.commit()
    return {"control_id": row.control_id, "answer": row.answer, "valid_until": row.valid_until.isoformat()}


@router.delete("/compliance/declarations/{control_id}", status_code=204)
async def compliance_undeclare(control_id: str, claims: dict = Depends(require_role(*WRITERS)),
                               db: AsyncSession = Depends(get_db)):
    if not await svc.remove_declaration(db, org_id_from_claims(claims), _actor(claims), control_id):
        raise HTTPException(status_code=404, detail="No hay una declaracion para ese control")
    await db.commit()
    return Response(status_code=204)


@router.get("/compliance/questionnaire.csv")
async def compliance_questionnaire_csv(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    ev = await svc.evaluate(db, org_id_from_claims(claims))
    return Response(content=svc.questionnaire_csv(ev), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="cuestionario-ciberseguro.csv"'})


@router.get("/compliance/attestation")
async def compliance_attestation(claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db)):
    """Atestado de cumplimiento firmado (Ed25519): se verifica sin TERO con verificar_evidencia.py."""
    doc = await svc.make_attestation(db, org_id_from_claims(claims), _actor(claims))
    await db.commit()
    return Response(content=json.dumps(doc, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="atestado-cumplimiento.json"'})
