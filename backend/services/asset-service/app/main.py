"""asset-service entrypoint: CMDB de activos (inventario)."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from app.schemas import AssetCreate, AssetUpdate, AssetOut, AssetGroupCreate, AssetGroupOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("asset-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("asset-service iniciado")
    yield


app = FastAPI(title="SentinelOps Asset Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "asset-service"}


@app.get("/assets", response_model=list[AssetOut])
async def get_assets(
    environment: str | None = None,
    criticality: str | None = None,
    include_inactive: bool = False,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    assets = await services.list_assets(db, environment, criticality, active_only=not include_inactive)
    return assets


@app.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    asset = await services.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    return asset


@app.post("/assets", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    asset = await services.create_asset(db, payload)
    await db.commit()
    logger.info("asset creado", extra={"asset_id": asset.id, "actor": claims.get("sub")})
    return asset


@app.patch("/assets/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    asset = await services.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    asset = await services.update_asset(db, asset, payload)
    await db.commit()
    return asset


@app.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_asset(
    asset_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    asset = await services.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    await services.deactivate_asset(db, asset)
    await db.commit()


@app.get("/asset-groups", response_model=list[AssetGroupOut])
async def get_groups(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_groups(db)


@app.post("/asset-groups", response_model=AssetGroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: AssetGroupCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    group = await services.create_group(db, payload)
    await db.commit()
    return group
