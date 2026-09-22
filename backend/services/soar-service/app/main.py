"""soar-service entrypoint: playbooks de respuesta (YAML -> Postgres, ver
app/playbook_loader.py) y su ejecucion (app/services.py). Acciones de
contencion defensiva unicamente, dry-run por defecto (app/actions/base.py)."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, SessionLocal, engine, Base
from backend.shared.logging import configure_logging
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
    return await services.list_playbooks(db)


@app.post("/playbooks", response_model=PlaybookOut, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    payload: PlaybookCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    playbook = await services.create_playbook(db, payload)
    await db.commit()
    return playbook


@app.patch("/playbooks/{playbook_id}", response_model=PlaybookOut)
async def update_playbook(
    playbook_id: str,
    payload: PlaybookUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    playbook = await services.get_playbook(db, playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook no encontrado")
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
    playbook = await services.get_playbook(db, playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook no encontrado")
    run = await services.run_playbook_manually(db, playbook, payload)
    await db.commit()
    logger.info("playbook corrido manualmente", extra={"playbook": playbook.name, "actor": claims.get("sub")})
    return run


@app.get("/runs", response_model=list[PlaybookRunOut])
async def list_runs(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_runs(db)


@app.get("/runs/{run_id}", response_model=PlaybookRunOut)
async def get_run(run_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    run = await services.get_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Corrida no encontrada")
    return run


@app.get("/pending-cases", response_model=list[PendingCaseOut])
async def list_pending_cases(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    """case-service (Fase 4) usa este endpoint para importar los casos que
    SOAR no pudo crear directamente porque case-service todavia no existia."""
    return await services.list_pending_cases(db)
