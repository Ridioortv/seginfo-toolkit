"""Pydantic schemas for notification-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

ChannelType = Literal["email", "slack_webhook", "generic_webhook"]


class ChannelCreate(BaseModel):
    name: str
    channel_type: ChannelType
    config: dict = Field(default_factory=dict, description="ej. {'webhook_url': ...} o {'smtp_to': ...}")
    enabled: bool = True


class ChannelOut(BaseModel):
    id: str
    name: str
    channel_type: str
    config: dict
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class NotifyRequest(BaseModel):
    subject: str
    body: str
    severity: str = "info"
    channel_ids: list[str] | None = Field(default=None, description="None = todos los canales habilitados")


class NotifyLogOut(BaseModel):
    id: str
    channel_id: str
    channel_type: str
    subject: str
    status: str
    error: str
    created_at: datetime

    class Config:
        from_attributes = True


class NotifyResult(BaseModel):
    results: list[NotifyLogOut]
