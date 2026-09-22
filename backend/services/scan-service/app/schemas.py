"""Pydantic schemas for scan-service."""
from datetime import datetime
from pydantic import BaseModel, Field
from app.models import ScannerType, ScanStatus


class ScanJobCreate(BaseModel):
    name: str = ""
    scanner_type: ScannerType
    target: str = Field(..., min_length=1, description="Host, CIDR o referencia de imagen segun el scanner")
    asset_id: str | None = None
    options: dict = Field(default_factory=dict)


class Finding(BaseModel):
    title: str
    description: str = ""
    severity: str = "info"
    cve_id: str | None = None
    port: int | None = None
    service: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None


class ScanJobOut(BaseModel):
    id: str
    name: str
    scanner_type: ScannerType
    target: str
    asset_id: str | None
    status: ScanStatus
    options: dict
    findings: list[dict]
    error_message: str
    created_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    class Config:
        from_attributes = True
