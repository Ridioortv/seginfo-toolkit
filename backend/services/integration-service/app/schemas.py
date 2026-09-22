"""Pydantic schemas for integration-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

ConnectorKind = Literal["firewall", "edr"]


class ConnectorCreate(BaseModel):
    name: str
    kind: ConnectorKind
    config: dict = Field(default_factory=dict, description="ej. {'base_url': 'https://fw.example/api', 'api_key': '...'}")
    enabled: bool = True


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


class IsolateHostRequest(BaseModel):
    hostname: str
    connector_id: str | None = None


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
