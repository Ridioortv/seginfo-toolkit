"""API de excepciones de riesgo (case-service). Leen y piden admin, soc_manager y analyst; deciden y revocan admin y
soc_manager (una vulnerabilidad critica solo la decide un admin, y nadie aprueba su propio pedido)."""
import json

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db
from backend.shared.tenancy import org_id_from_claims
from app import exception_service as svc
from app.dependencies import require_role

router = APIRouter()
READERS = ("admin", "soc_manager", "analyst")
DECIDERS = ("admin", "soc_manager")


class RequestIn(BaseModel):
    vuln_id: str = Field(min_length=1, max_length=36)
    justification: str = Field(min_length=1, max_length=3000)
    compensating_controls: str = Field(default="", max_length=3000)
    days: int = Field(default=90, ge=1, le=365)


class NoteIn(BaseModel):
    note: str = Field(default="", max_length=1000)


def _actor(claims: dict) -> str:
    return claims.get("email") or claims.get("sub", "")


def _fail(exc: svc.ExceptionError):
    raise HTTPException(status_code=exc.status, detail=str(exc))


async def _row(db: AsyncSession, claims: dict, exception_id: str):
    row = await svc.get(db, org_id_from_claims(claims), exception_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Excepcion no encontrada")
    return row


@router.get("/risk-exceptions/summary")
async def exceptions_summary(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    if await svc.expire_due(db, org):
        await db.commit()
    return svc.summarize(await svc.list_rows(db, org))


@router.get("/risk-exceptions/register.csv")
async def exceptions_register(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    rows = await svc.list_rows(db, org_id_from_claims(claims))
    return Response(content=svc.register_csv(rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="registro-excepciones-de-riesgo.csv"'})


@router.get("/risk-exceptions")
async def exceptions_list(status: str | None = None, vuln_id: str | None = None, claims: dict = Depends(require_role(*READERS)),
                          db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    if await svc.expire_due(db, org):
        await db.commit()
    return [svc.view(r, full=False) for r in await svc.list_rows(db, org, status, vuln_id)]


@router.post("/risk-exceptions", status_code=201)
async def exceptions_request(payload: RequestIn, claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    try:
        row = await svc.request(db, org_id_from_claims(claims), _actor(claims), payload.vuln_id, payload.justification,
                                payload.compensating_controls, payload.days)
    except svc.ExceptionError as exc:
        _fail(exc)
    await db.commit()
    return svc.view(row)


@router.get("/risk-exceptions/{exception_id}")
async def exceptions_detail(exception_id: str, claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    return svc.view(await _row(db, claims, exception_id))


@router.post("/risk-exceptions/{exception_id}/approve")
async def exceptions_approve(exception_id: str, payload: NoteIn, claims: dict = Depends(require_role(*DECIDERS)),
                             db: AsyncSession = Depends(get_db)):
    row = await _row(db, claims, exception_id)
    try:
        await svc.approve(db, org_id_from_claims(claims), _actor(claims), claims.get("role", ""), row, payload.note)
    except svc.ExceptionError as exc:
        await db.rollback()
        _fail(exc)
    await db.commit()
    return svc.view(row)


@router.post("/risk-exceptions/{exception_id}/reject")
async def exceptions_reject(exception_id: str, payload: NoteIn, claims: dict = Depends(require_role(*DECIDERS)),
                            db: AsyncSession = Depends(get_db)):
    row = await _row(db, claims, exception_id)
    try:
        await svc.reject(db, org_id_from_claims(claims), _actor(claims), claims.get("role", ""), row, payload.note)
    except svc.ExceptionError as exc:
        await db.rollback()
        _fail(exc)
    await db.commit()
    return svc.view(row)


@router.post("/risk-exceptions/{exception_id}/withdraw")
async def exceptions_withdraw(exception_id: str, claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    row = await _row(db, claims, exception_id)
    try:
        await svc.withdraw(db, org_id_from_claims(claims), _actor(claims), row)
    except svc.ExceptionError as exc:
        _fail(exc)
    await db.commit()
    return svc.view(row)


@router.post("/risk-exceptions/{exception_id}/revoke")
async def exceptions_revoke(exception_id: str, payload: NoteIn, claims: dict = Depends(require_role(*DECIDERS)),
                            db: AsyncSession = Depends(get_db)):
    row = await _row(db, claims, exception_id)
    try:
        await svc.revoke(db, org_id_from_claims(claims), _actor(claims), row, payload.note)
    except svc.ExceptionError as exc:
        await db.rollback()
        _fail(exc)
    await db.commit()
    return svc.view(row)


@router.get("/risk-exceptions/{exception_id}/attestation")
async def exceptions_attestation(exception_id: str, claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    row = await _row(db, claims, exception_id)
    if row.status == "pending":
        raise HTTPException(status_code=404, detail="Esta excepcion todavia no tiene una decision")
    doc = await svc.make_attestation(db, org_id_from_claims(claims), row)
    return Response(content=json.dumps(doc, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="prueba-excepcion-{row.id[:8]}.json"'})
