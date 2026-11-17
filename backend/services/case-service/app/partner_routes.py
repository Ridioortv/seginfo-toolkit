"""API de la consola multicliente (case-service). Solo la usa la gente de la organizacion partner."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from backend.shared.tenancy import org_id_from_claims
from app import partner_service as svc
from app.dependencies import require_role

router = APIRouter()
READERS = ("admin", "soc_manager", "analyst", "viewer")
EXPORTERS = ("admin", "soc_manager")


def _partner_org(claims: dict) -> str:
    if claims.get("partner_org_id"):
        raise HTTPException(status_code=403, detail="Volve a tu consola de partner para hacer esto")
    return org_id_from_claims(claims)


@router.get("/partner/overview")
async def partner_overview(days: int = Query(30, ge=7, le=365), claims: dict = Depends(require_role(*READERS))):
    try:
        return await svc.overview(_partner_org(claims), days)
    except svc.PartnerError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail)


@router.get("/partner/usage.csv")
async def partner_usage(days: int = Query(30, ge=7, le=365), claims: dict = Depends(require_role(*EXPORTERS))):
    try:
        data = await svc.overview(_partner_org(claims), days)
    except svc.PartnerError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(content=svc.usage_csv(data), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="uso-por-cliente-{stamp}.csv"'})
