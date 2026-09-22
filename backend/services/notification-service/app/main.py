"""notification-service entrypoint: canales configurables (email/Slack/
webhook generico) para avisar de alertas/incidentes. Por defecto en modo
DRY-RUN (NOTIFICATION_DRY_RUN=true): registra la notificacion que *se
enviaria* sin hacer ninguna llamada de red real, igual que el patron de
soar-service."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from app.schemas import ChannelCreate, ChannelOut, NotifyRequest, NotifyResult, NotifyLogOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("notification-service")
notifications_sent_total = Counter("notification_sent_total", "Notificaciones procesadas", ["channel_type", "status"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("notification-service iniciado", extra={"dry_run": services.dry_run_enabled()})
    yield


app = FastAPI(title="SentinelOps Notification Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "notification-service", "dry_run": services.dry_run_enabled()}


@app.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
async def create_channel(
    payload: ChannelCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    channel = await services.create_channel(db, payload)
    await db.commit()
    return channel


@app.get("/channels", response_model=list[ChannelOut])
async def list_channels(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_channels(db)


@app.post("/notify", response_model=NotifyResult)
async def notify(
    payload: NotifyRequest,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    logs = await services.notify(db, payload)
    await db.commit()
    for log in logs:
        notifications_sent_total.labels(channel_type=log.channel_type, status=log.status).inc()
    return NotifyResult(results=[NotifyLogOut.model_validate(l) for l in logs])


@app.get("/logs", response_model=list[NotifyLogOut])
async def list_logs(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_logs(db)
