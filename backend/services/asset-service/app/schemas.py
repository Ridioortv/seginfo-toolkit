"""Pydantic schemas for asset-service."""
from datetime import datetime
from pydantic import BaseModel, Field
from app.models import AssetCriticality, AssetEnvironment


class AssetCreate(BaseModel):
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    os_name: str = ""
    os_version: str = ""
    environment: AssetEnvironment = AssetEnvironment.production
    criticality: AssetCriticality = AssetCriticality.medium
    owner: str = ""
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


class AssetUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    environment: AssetEnvironment | None = None
    criticality: AssetCriticality | None = None
    owner: str | None = None
    tags: list[str] | None = None
    notes: str | None = None
    is_active: bool | None = None


class AssetOut(BaseModel):
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    os_name: str
    os_version: str
    environment: AssetEnvironment
    criticality: AssetCriticality
    owner: str
    tags: list[str]
    is_active: bool
    notes: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetGroupCreate(BaseModel):
    name: str
    description: str = ""
    asset_ids: list[str] = Field(default_factory=list)


class AssetGroupOut(BaseModel):
    id: str
    name: str
    description: str
    asset_ids: list[str]
    created_at: datetime

    class Config:
        from_attributes = True
