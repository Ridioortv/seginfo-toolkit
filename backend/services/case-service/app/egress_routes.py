"""API de la prueba de soberania (case-service). Los servicios informan por /internal con JWT de servicio;
las personas (admin, soc_manager) consultan el estado, hacen la prueba de red y bajan el atestado firmado."""
import json

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db
from backend.shared.service_auth import require_service_token
from backend.shared.tenancy import org_id_from_claims
from app import egress_service as egress
from app import services
from app.dependencies import require_role

router = APIRouter()
READERS = ("admin", "soc_manager")


class DestinationIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    kind: str = Field(default="http", max_length=20)
    count: int = Field(default=0, ge=0)
    blocked: int = Field(default=0, ge=0)
    first_seen: str = ""
    last_seen: str = ""
    purposes: list[str] = Field(default_factory=list, max_length=5)


class EgressReportIn(BaseModel):
    service: str = Field(min_length=2, max_length=60)
    instance: str = Field(default="", max_length=120)
    boot: str = Field(default="", max_length=40)
    isolated: bool = False
    allowlist: list[str] = Field(default_factory=list, max_length=50)
    interval_seconds: int = 60
    destinations: list[DestinationIn] = Field(default_factory=list, max_length=egress.MAX_DEST_PER_REPORT)


def _actor(claims: dict) -> str:
    return claims.get("email") or claims.get("sub", "")


@router.post("/internal/egress/report", status_code=204)
async def egress_report(payload: EgressReportIn, claims: dict = Depends(require_service_token), db: AsyncSession = Depends(get_db)):
    """Cada servicio informa, cada tanto, a que destinos externos hablo (solo nombres de host) y si esta aislado.
    El nombre del servicio debe coincidir con el del JWT: un servicio no puede informar por otro."""
    if str(claims.get("sub", "")) != f"system:{payload.service}":
        raise HTTPException(status_code=403, detail="El servicio no coincide con el token")
    result = await egress.ingest_report(db, payload.model_dump())
    changed = result["mode_changed"]
    if changed:
        await egress.record_mode_change(db, await services.list_organization_ids(), payload.service, *changed)
    await db.commit()
    return Response(status_code=204)


@router.get("/sovereignty/status")
async def sovereignty_status(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    return {**await egress.status(db), "limits": egress.LIMITS}


@router.get("/sovereignty/catalog")
async def sovereignty_catalog(claims: dict = Depends(require_role(*READERS))):
    return egress.catalog_view()


@router.post("/sovereignty/probe")
async def sovereignty_probe(claims: dict = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    """Intenta salir a internet desde la red de TERO (conexiones de prueba, sin enviar datos) y lo deja anotado
    en la cadena de custodia."""
    result = await egress.run_probe(db, _actor(claims), org_id_from_claims(claims))
    await db.commit()
    return result


@router.get("/sovereignty/attestation")
async def sovereignty_attestation(claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    """Atestado de soberania firmado (Ed25519): se verifica sin TERO con verificar_evidencia.py."""
    doc = await egress.make_attestation(db, org_id_from_claims(claims), _actor(claims))
    await db.commit()
    return Response(content=json.dumps(doc, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="atestado-soberania.json"'})
