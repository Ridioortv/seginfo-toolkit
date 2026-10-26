"""Pydantic schemas for notification-service."""
from datetime import datetime
from typing import Literal
import re
from pydantic import BaseModel, Field, field_validator

ChannelType = Literal["email", "slack_webhook", "generic_webhook"]


def _channel_name(v: str | None) -> str | None:
    """Nombre obligatorio y que entre en la columna (255): antes se aceptaba
    vacio y uno largo terminaba en error 500."""
    if v is None:
        return None
    v = v.strip()
    if not v:
        raise ValueError("El nombre del canal no puede estar vacio")
    if len(v) > 255:
        raise ValueError("El nombre del canal admite hasta 255 caracteres")
    return v


class ChannelCreate(BaseModel):
    name: str
    channel_type: ChannelType
    config: dict = Field(default_factory=dict, description="ej. {'webhook_url': ...} o {'smtp_to': ...}")
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _v_name(cls, v):
        return _channel_name(v)


class ChannelUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def _v_name(cls, v):
        return _channel_name(v)


class ChannelOut(BaseModel):
    id: str
    name: str
    channel_type: str
    config: dict
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class NotifyAttachment(BaseModel):
    """Adjunto opcional (ej. un PDF de reporte). Solo se envia realmente
    en canales tipo 'email' -- los webhooks/Slack lo ignoran, ya que esos
    protocolos no tienen un concepto de adjunto binario aca."""
    filename: str
    content_type: str = "application/octet-stream"
    content_base64: str


class NotifyRequest(BaseModel):
    subject: str
    body: str
    severity: str = "info"
    channel_ids: list[str] | None = Field(default=None, description="None = todos los canales habilitados")
    attachments: list[NotifyAttachment] | None = Field(default=None, description="Adjuntos opcionales, solo aplicados en canales tipo 'email'")
    # Opcional -- POST /notify lo deriva del JWT si no viene; POST
    # /internal/notify (sin JWT, ver main.py) depende de que el caller
    # (soar-service, report-service) lo mande explicitamente. Si falta, se
    # asume la organizacion default (ver backend/shared/tenancy.py).
    organization_id: str | None = None


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

    @field_validator("error")
    @classmethod
    def _hide_urls(cls, value: str) -> str:
        """El webhook_url es una credencial (se enmascara para roles bajos en
        GET /channels): ninguna URL completa sale en el error de un envio, ni
        siquiera en filas guardadas antes de este fix."""
        return re.sub(r"https?://[^\s'\"<>]+", "[url oculta]", value or "")


class NotifyResult(BaseModel):
    results: list[NotifyLogOut]
