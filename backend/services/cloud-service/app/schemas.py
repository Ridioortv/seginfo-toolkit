"""Pydantic schemas for cloud-service. CloudAccountOut jamas incluye las
credenciales (ni en texto plano ni cifradas) -- solo access_key_id_masked,
ver app/services.py::mask_access_key_id."""
import re
from datetime import datetime
from pydantic import BaseModel, field_validator
from app.models import CloudFindingType, CloudProvider, CloudResourceType, FindingSeverity


class CloudAccountCreate(BaseModel):
    name: str
    region: str = "us-east-1"
    access_key_id: str
    secret_access_key: str

    # Antes se guardaba cualquier cosa (nombre vacio, region "mars-1", clave de
    # 1 caracter) y el error recien aparecia en la primera sincronizacion.
    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 255:
            raise ValueError("El nombre de la cuenta es obligatorio (hasta 255 caracteres)")
        return v

    @field_validator("region")
    @classmethod
    def _region(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d{1,2}", v):
            raise ValueError("La region no tiene el formato de AWS (ej. us-east-1, sa-east-1)")
        return v

    @field_validator("access_key_id")
    @classmethod
    def _access_key(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[A-Z0-9]{16,128}", v):
            raise ValueError("El Access Key ID tiene un formato invalido (suele empezar con AKIA o ASIA y tener 20 caracteres)")
        return v

    @field_validator("secret_access_key")
    @classmethod
    def _secret(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 16 or len(v) > 256 or any(c.isspace() for c in v):
            raise ValueError("El Secret Access Key tiene un formato invalido (sin espacios, al menos 16 caracteres)")
        return v


class CloudAccountOut(BaseModel):
    id: str
    name: str
    provider: CloudProvider
    region: str
    access_key_id_masked: str
    is_enabled: bool
    last_sync_at: datetime | None
    last_sync_status: str
    last_sync_error: str
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


class CloudResourceOut(BaseModel):
    id: str
    cloud_account_id: str
    resource_type: CloudResourceType
    external_id: str
    name: str
    region: str
    resource_metadata: dict
    is_active: bool
    first_seen_at: datetime
    last_seen_at: datetime

    class Config:
        from_attributes = True


class CloudFindingOut(BaseModel):
    id: str
    cloud_account_id: str
    resource_external_id: str
    finding_type: CloudFindingType
    severity: FindingSeverity
    detail: str
    created_at: datetime
    is_acknowledged: bool
    acknowledged_by: str

    class Config:
        from_attributes = True


class CloudFindingUpdate(BaseModel):
    is_acknowledged: bool
