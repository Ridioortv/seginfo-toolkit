"""API del tablero ejecutivo (case-service). Lo ven todos los roles; firmar el informe lo hacen admin y soc_manager."""
import json

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db
from backend.shared.tenancy import org_id_from_claims
from app import executive_service as svc
from app.dependencies import require_role

router = APIRouter()
READERS = ("admin", "soc_manager", "analyst", "viewer")
SIGNERS = ("admin", "soc_manager")


@router.get("/executive/summary")
async def executive_summary(days: int = Query(30, ge=7, le=365), claims: dict = Depends(require_role(*READERS)),
                            db: AsyncSession = Depends(get_db)):
    return await svc.summary(db, org_id_from_claims(claims), days)


@router.get("/executive/trend")
async def executive_trend(days: int = Query(90, ge=7, le=400), claims: dict = Depends(require_role(*READERS)),
                          db: AsyncSession = Depends(get_db)):
    return {"items": await svc.trend(db, org_id_from_claims(claims), days)}


@router.post("/executive/report")
async def executive_report(days: int = Query(30, ge=7, le=365), claims: dict = Depends(require_role(*SIGNERS)),
                           db: AsyncSession = Depends(get_db)):
    """Calcula el informe, lo firma y deja el hecho en la cadena de custodia. Devuelve el atestado (JSON firmado)."""
    doc = await svc.make_report(db, org_id_from_claims(claims), claims.get("email") or claims.get("sub", ""), days)
    await db.commit()
    return Response(content=json.dumps(doc, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="informe-ejecutivo.json"'})
