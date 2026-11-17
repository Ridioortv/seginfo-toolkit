"""API de tickets vinculados (integration-service).

Usuarios: crear el ticket de una vulnerabilidad o de un caso, ver los vinculos, sincronizar, probar la conexion y generar el
secreto del webhook. Publica: el webhook que llama Jira/ServiceNow cuando un ticket cambia (autenticado por el secreto)."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db
from backend.shared.rate_limit import check_rate_limit
from backend.shared.tenancy import org_id_from_claims
from app import services, ticket_providers as providers, ticket_service as svc
from app.dependencies import get_current_claims, require_role
from app.models import Connector
from app.schemas import TicketLinkCreate

router = APIRouter()
public_router = APIRouter()
WRITERS = ("admin", "soc_manager", "analyst")


def _actor(claims: dict) -> str:
    return claims.get("email") or claims.get("sub", "")


async def _names(db: AsyncSession, org: str) -> dict[str, str]:
    rows = (await db.execute(select(Connector.id, Connector.name).where(Connector.organization_id == org))).all()
    return {i: n for i, n in rows}


@router.post("/ticket-links", status_code=201)
async def create_link(payload: TicketLinkCreate, claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    try:
        link = await svc.create_for_subject(db, org, _actor(claims), payload.subject_type, payload.subject_id, payload.connector_id)
    except svc.TicketError as exc:
        await db.rollback()
        raise HTTPException(status_code=exc.status, detail={"message": str(exc), **exc.extra} if exc.extra else str(exc))
    await db.commit()
    return svc.view(link, (await _names(db, org)).get(link.connector_id, ""))


@router.get("/ticket-links")
async def list_links(subject_type: str | None = None, subject_id: str | None = None, state: str | None = None,
                     limit: int = Query(200, ge=1, le=500), claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    names = await _names(db, org)
    return [svc.view(l, names.get(l.connector_id, "")) for l in await svc.list_links(db, org, subject_type, subject_id, state, limit)]


@router.post("/ticket-links/sync")
async def sync_all(claims: dict = Depends(require_role("admin", "soc_manager")), db: AsyncSession = Depends(get_db)):
    """Pregunta ahora al sistema de tickets por el estado de todos los tickets abiertos de la organizacion."""
    if svc._dry():
        raise HTTPException(status_code=409, detail="El modo de prueba (INTEGRATION_DRY_RUN) esta activo: no se consulta ningun sistema real.")
    result = await svc.sync_open(db, org_id_from_claims(claims))
    await db.commit()
    return result


@router.post("/ticket-links/{link_id}/sync")
async def sync_one(link_id: str, claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    link = await db.get(svc.TicketLink, link_id)
    if link is None or link.organization_id != org:
        raise HTTPException(status_code=404, detail="Vinculo no encontrado")
    if svc._dry():
        raise HTTPException(status_code=409, detail="El modo de prueba (INTEGRATION_DRY_RUN) esta activo: no se consulta ningun sistema real.")
    await svc.sync_link(db, link)
    await db.commit()
    return svc.view(link, (await _names(db, org)).get(link.connector_id, ""))


@router.post("/connectors/{connector_id}/test")
async def test_connector(connector_id: str, claims: dict = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    """Prueba la URL y las credenciales del conector de tickets sin crear nada."""
    connector = await services.get_connector(db, connector_id, org_id_from_claims(claims))
    if connector is None or connector.kind != "ticketing":
        raise HTTPException(status_code=404, detail="Conector de tickets no encontrado")
    if svc._dry():
        return {"ok": False, "dry_run": True, "message": "Modo de prueba activo (INTEGRATION_DRY_RUN=true): no se llamo al sistema real."}
    try:
        return {"ok": True, "dry_run": False, "message": await providers.check(svc._decrypted(connector))}
    except providers.ProviderError as exc:
        return {"ok": False, "dry_run": False, "message": str(exc)}


@router.post("/connectors/{connector_id}/webhook-secret")
async def webhook_secret(connector_id: str, claims: dict = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    """Genera (o cambia) el secreto del webhook entrante. Se muestra UNA vez: despues solo queda su hash."""
    connector = await services.get_connector(db, connector_id, org_id_from_claims(claims))
    if connector is None or connector.kind != "ticketing":
        raise HTTPException(status_code=404, detail="Conector de tickets no encontrado")
    token = svc.new_webhook_secret(connector)
    await db.commit()
    return {"path": f"/public/ticket-webhooks/{connector.id}/{token}",
            "note": "Guardalo ahora: no se vuelve a mostrar. Si lo perdes, genera uno nuevo (el anterior deja de valer)."}


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "")) or "desconocida"


@public_router.post("/public/ticket-webhooks/{connector_id}/{token}")
async def ticket_webhook(connector_id: str, token: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Aviso de Jira/ServiceNow: "este ticket cambio". Se autentica por el secreto de la URL y el estado se vuelve a pedir al
    sistema externo (el contenido del aviso solo dice QUE ticket cambio)."""
    ok_ip = await check_rate_limit(f"ticket-webhook-ip:{_client_ip(request)}", 300, 3600)
    ok_conn = await check_rate_limit(f"ticket-webhook-conn:{connector_id[:36]}", 600, 3600)
    if not (ok_ip and ok_conn):
        raise HTTPException(status_code=429, detail="Demasiados avisos. Proba de nuevo en un rato.")
    connector = await db.get(Connector, connector_id)
    if connector is None or connector.kind != "ticketing" or not connector.enabled or not svc.webhook_secret_ok(connector, token):
        raise HTTPException(status_code=404, detail="No encontrado")  # igual para "no existe" y "secreto incorrecto"
    try:
        body = await request.json()
    except ValueError:
        body = {}
    if svc._dry():
        return {"matched": 0, "synced": 0, "dry_run": True}
    result = await svc.handle_webhook(db, connector, body if isinstance(body, dict) else {})
    await db.commit()
    return result
