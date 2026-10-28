"""Pydantic schemas for integration-service."""
from datetime import datetime
from typing import Literal
import re
from pydantic import BaseModel, Field, field_validator


def _hide_urls(value: str) -> str:
    return re.sub(r"https?://[^\s'\"<>]+", "[url oculta]", value or "")

ConnectorKind = Literal["firewall", "edr", "ticketing"]


def _check_provider(config: dict | None) -> dict | None:
    provider = (config or {}).get("provider")
    if provider is not None and str(provider).lower() not in ("jira", "servicenow"):
        raise ValueError("El proveedor de tickets debe ser 'jira' o 'servicenow'")
    return config


class ConnectorCreate(BaseModel):
    name: str
    kind: ConnectorKind
    config: dict = Field(default_factory=dict, description="ej. {'base_url': 'https://fw.example/api', 'api_key': '...'}")
    enabled: bool = True

    @field_validator("config")
    @classmethod
    def _v_config(cls, v):
        return _check_provider(v)


class ConnectorUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    enabled: bool | None = None

    @field_validator("config")
    @classmethod
    def _v_config(cls, v):
        return _check_provider(v)


class ConnectorOut(BaseModel):
    id: str
    name: str
    kind: str
    config: dict
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class BlockIpRequest(BaseModel):
    ip: str
    connector_id: str | None = None
    # Opcional -- estos endpoints /internal/actions/* no llevan JWT (ver
    # main.py), asi que soar-service lo manda explicitamente. Si falta, se
    # asume la organizacion default (ver backend/shared/tenancy.py).
    organization_id: str | None = None


class IsolateHostRequest(BaseModel):
    hostname: str
    connector_id: str | None = None
    organization_id: str | None = None


class ActionLogOut(BaseModel):
    id: str
    connector_id: str
    action: str
    target: str
    status: str
    error: str
    created_at: datetime

    class Config:
        from_attributes = True

    @field_validator("error")
    @classmethod
    def _error_without_urls(cls, v: str) -> str:
        return _hide_urls(v)


class CreateTicketRequest(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"
    connector_id: str | None = None
    organization_id: str | None = None


class TicketLogOut(BaseModel):
    id: str
    connector_id: str
    title: str
    priority: str
    status: str
    external_key: str
    external_url: str
    error: str
    created_at: datetime

    class Config:
        from_attributes = True

    @field_validator("error")
    @classmethod
    def _error_without_urls(cls, v: str) -> str:
        return _hide_urls(v)


class TicketLinkCreate(BaseModel):
    subject_type: Literal["vulnerability", "case"]
    subject_id: str = Field(min_length=1, max_length=36)
    connector_id: str | None = None
