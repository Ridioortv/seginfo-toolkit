"""integration-service entrypoint: conectores genericos de contencion
(firewall/EDR, tipo webhook REST) para las acciones que soar-service
dispara desde sus playbooks. Por defecto en modo DRY-RUN
(INTEGRATION_DRY_RUN=true): jamas llama a un sistema real todavia, ver
app/services.py. Expone endpoints internos sin auth de usuario (pensados
para llamadas servicio-a-servicio desde soar-service dentro de la red de
docker-compose, mismo patron que el /internal/rule-tags de siem-service) y
endpoints de administracion de conectores que si requieren rol admin."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import text
from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import (
    ConnectorCreate, ConnectorOut, BlockIpRequest, IsolateHostRequest, ActionLogOut,
    CreateTicketRequest, TicketLogOut,
)
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("integration-service")
actions_total = Counter("integration_action_total", "Acciones de contencion procesadas", ["action", "status"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE connectors ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text(
            "ALTER TABLE integration_action_logs ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        ))
        await conn.execute(text(
            "ALTER TABLE integration_ticket_logs ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        ))
        await conn.execute(text(
            f"UPDATE connectors SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text(
            f"UPDATE integration_action_logs SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text(
            f"UPDATE integration_ticket_logs SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    logger.info("integration-service iniciado", extra={"dry_run": services.dry_run_enabled()})
    yield


app = FastAPI(title="SentinelOps Integration Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "integration-service", "dry_run": services.dry_run_enabled()}


@app.post("/connectors", response_model=ConnectorOut, status_code=status.HTTP_201_CREATED)
async def create_connector(
    payload: ConnectorCreate,
    claims: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    connector = await services.create_connector(db, payload, org_id_from_claims(claims))
    await db.commit()
    return connector


@app.get("/connectors", response_model=list[ConnectorOut])
async def list_connectors(kind: str | None = None, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_connectors(db, org_id_from_claims(claims), kind)


@app.get("/actions", response_model=list[ActionLogOut])
async def list_action_logs(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_action_logs(db, org_id_from_claims(claims))


@app.post("/internal/actions/block-ip", response_model=ActionLogOut)
async def internal_block_ip(payload: BlockIpRequest, db: AsyncSession = Depends(get_db)):
    """Endpoint interno (sin auth de usuario) para que soar-service dispare
    la contencion real -- o simulada, si INTEGRATION_DRY_RUN=true -- de una
    IP marcada como origen malicioso en una alerta."""
    organization_id = payload.organization_id or DEFAULT_ORGANIZATION_ID
    log = await services.block_ip(db, payload.ip, organization_id, payload.connector_id)
    await db.commit()
    actions_total.labels(action="block_ip", status=log.status).inc()
    return log


@app.post("/internal/actions/isolate-host", response_model=ActionLogOut)
async def internal_isolate_host(payload: IsolateHostRequest, db: AsyncSession = Depends(get_db)):
    """Endpoint interno (sin auth de usuario) para que soar-service dispare
    el aislamiento real -- o simulado -- de un host comprometido."""
    organization_id = payload.organization_id or DEFAULT_ORGANIZATION_ID
    log = await services.isolate_host(db, payload.hostname, organization_id, payload.connector_id)
    await db.commit()
    actions_total.labels(action="isolate_host", status=log.status).inc()
    return log


@app.get("/tickets", response_model=list[TicketLogOut])
async def list_tickets(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_ticket_logs(db, org_id_from_claims(claims))


@app.post("/internal/actions/create-ticket", response_model=TicketLogOut)
async def internal_create_ticket(payload: CreateTicketRequest, db: AsyncSession = Depends(get_db)):
    """Endpoint interno (sin auth de usuario) para que soar-service abra
    un ticket -- o lo simule -- en el sistema de ticketing configurado
    (ej. Jira, via un conector kind='ticketing'; ver app/services.py
    _call_jira)."""
    organization_id = payload.organization_id or DEFAULT_ORGANIZATION_ID
    log = await services.create_ticket(
        db, payload.title, payload.description, payload.priority, payload.connector_id, organization_id
    )
    await db.commit()
    actions_total.labels(action="create_ticket", status=log.status).inc()
    return log
