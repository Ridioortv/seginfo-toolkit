"""Pydantic schemas for asset-service."""
import ipaddress
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, model_validator
from app.models import AssetCriticality, AssetEnvironment


def _clean_ip(v: str | None) -> str | None:
    """La IP se usa luego como objetivo de escaneo: tiene que ser una IPv4/IPv6
    valida (la API aceptaba "999.1.1.1" o texto cualquiera). Vacia = sin IP."""
    if v is None:
        return None
    v = v.strip()
    if not v:
        return ""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ValueError(f"'{v}' no es una direccion IP valida (ej. 192.168.1.10)")


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

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        return _clean_ip(v) or ""

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

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        return _clean_ip(v)


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
