"""Business logic for asset-service: CRUD sobre el CMDB de activos."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Asset, AssetGroup


async def list_assets(
    db: AsyncSession, environment: str | None = None, criticality: str | None = None, active_only: bool = True
) -> list[Asset]:
    query = select(Asset)
    if active_only:
        query = query.where(Asset.is_active.is_(True))
    if environment:
        query = query.where(Asset.environment == environment)
    if criticality:
        query = query.where(Asset.criticality == criticality)
    result = await db.execute(query.order_by(Asset.hostname))
    return list(result.scalars().all())


async def get_asset(db: AsyncSession, asset_id: str) -> Asset | None:
    return await db.get(Asset, asset_id)


async def get_assets_by_ids(db: AsyncSession, asset_ids: list[str]) -> list[Asset]:
    if not asset_ids:
        return []
    result = await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
    return list(result.scalars().all())


async def create_asset(db: AsyncSession, payload) -> Asset:
    asset = Asset(**payload.model_dump())
    db.add(asset)
    await db.flush()
    await db.refresh(asset)
    return asset


async def update_asset(db: AsyncSession, asset: Asset, payload) -> Asset:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    await db.flush()
    await db.refresh(asset)
    return asset


async def deactivate_asset(db: AsyncSession, asset: Asset) -> Asset:
    asset.is_active = False
    await db.flush()
    return asset


async def list_groups(db: AsyncSession) -> list[AssetGroup]:
    result = await db.execute(select(AssetGroup).order_by(AssetGroup.name))
    return list(result.scalars().all())


async def create_group(db: AsyncSession, payload) -> AssetGroup:
    group = AssetGroup(**payload.model_dump())
    db.add(group)
    await db.flush()
    await db.refresh(group)
    return group
