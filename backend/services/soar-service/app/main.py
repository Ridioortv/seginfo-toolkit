"""soar-service entrypoint: playbooks de respuesta (YAML -> Postgres, ver
app/playbook_loader.py) y su ejecucion (app/services.py). Acciones de
contencion defensiva unicamente, dry-run por defecto (app/actions/base.py)."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, SessionLocal, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import (
    PlaybookCreate, PlaybookUpdate, PlaybookOut, PlaybookRunOut,
    TriggerRequest, TriggerResponse, ManualRunRequest, PendingCaseOut,
)
from app.dependencies import get_current_claims, require_role
from app import services, playbook_loader

logger = configure_logging("soar-service")
playbooks_triggered_total = Counter("soar_playbooks_triggered_total", "Playbooks disparados", ["status"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # A diferencia del resto de las tablas de este proyecto, playbooks
        # viejos (creados antes de multi-tenancy) NO se backfillean a
        # DEFAULT_ORGANIZATION_ID -- se dejan en NULL, que aca significa
        # "global/built-in", exactamente el mismo estado en el que ya
        # estaban de forma implicita (visibles para todos, sin tenant).
        await conn.execute(text("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text("ALTER TABLE playbook_runs ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text("ALTER TABLE pending_cases ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text(
            f"UPDATE playbook_runs SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text(
            f"UPDATE pending_cases SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    async with SessionLocal() as session:
        synced = await playbook_loader.sync_playbooks_from_yaml(session)
        await session.commit()
        logger.info("playbooks sincronizados desde YAML", extra={"count": synced})
    logger.info("soar-service iniciado")
    yield


app = FastAPI(title="SentinelOps SOAR Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "soar-service"}


@app.post("/trigger", response_model=TriggerResponse)
async def trigger(payload: TriggerRequest, db: AsyncSession = Depends(get_db)):
    """Llamado por siem-service ante cada alerta nueva (best-effort, ver
    siem-service/app/services.py _notify_soar)."""
    matched, runs = await services.trigger_playbooks(db, payload)
    await db.commit()
    for run in runs:
        playbooks_triggered_total.labels(status=run.status.value).inc()
    return TriggerResponse(playbooks_matched=matched, runs=runs)


@app.get("/playbooks", response_model=list[PlaybookOut])
async def list_playbooks(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_playbooks(db, org_id_from_claims(claims))


@app.post("/playbooks", response_model=PlaybookOut, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    payload: PlaybookCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    playbook = await services.create_playbook(db, payload, org_id_from_claims(claims))
    await db.commit()
    return playbook


@app.patch("/playbooks/{playbook_id}", response_model=PlaybookOut)
async def update_playbook(
    playbook_id: str,
    payload: PlaybookUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    playbook = await services.get_playbook(db, playbook_id, org_id_from_claims(claims))
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook no encontrado")
    # Los playbooks globales (organization_id NULL, sincronizados desde YAML)
    # son de solo lectura para cualquiera que no sea platform_admin -- de lo
    # contrario un admin de UNA organizacion podria editar un playbook que
    # ven y corren TODAS las demas.
    if playbook.organization_id is None and not claims.get("platform_admin"):
        raise HTTPException(status_code=403, detail="Solo un administrador de plataforma puede editar un playbook global")
    playbook = await services.update_playbook(db, playbook, payload)
    await db.commit()
    return playbook


@app.post("/playbooks/{playbook_id}/run", response_model=PlaybookRunOut)
async def run_playbook_manually(
    playbook_id: str,
    payload: ManualRunRequest,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    organization_id = org_id_from_claims(claims)
    playbook = await services.get_playbook(db, playbook_id, organization_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook no encontrado")
    run = await services.run_playbook_manually(db, playbook, payload, organization_id)
    await db.commit()
    logger.info("playbook corrido manualmente", extra={"playbook": playbook.name, "actor": claims.get("sub")})
    return run


@app.get("/runs", response_model=list[PlaybookRunOut])
async def list_runs(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_runs(db, org_id_from_claims(claims))


@app.get("/runs/{run_id}", response_model=PlaybookRunOut)
async def get_run(run_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    run = await services.get_run(db, run_id, org_id_from_claims(claims))
    if run is None:
        raise HTTPException(status_code=404, detail="Corrida no encontrada")
    return run


@app.get("/pending-cases", response_model=list[PendingCaseOut])
async def list_pending_cases(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    """case-service (Fase 4) usa este endpoint para importar los casos que
    SOAR no pudo crear directamente porque case-service todavia no existia."""
    return await services.list_pending_cases(db, org_id_from_claims(claims))
