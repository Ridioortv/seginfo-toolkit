"""Pydantic schemas for asset-service."""
from datetime import datetime
from pydantic import BaseModel, Field, model_validator
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

    @model_validator(mode="after")
    def _needs_hostname_or_ip(self):
        """Un activo sin hostname NI IP no se puede identificar (la pantalla ya lo
        frena, pero la API aceptaba el POST directo y llenaba el inventario de filas
        vacias). Se limpian los espacios y se exige al menos uno de los dos."""
        self.hostname = self.hostname.strip()
        self.ip_address = self.ip_address.strip()
        if not self.hostname and not self.ip_address:
            raise ValueError("Indica al menos el hostname o la direccion IP del activo")
        return self


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
