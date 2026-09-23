"""Pydantic schemas for scan-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, model_validator
from app.models import ScannerType, ScanStatus

ScanFrequency = Literal["daily", "weekly"]


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


class ScanScheduleCreate(BaseModel):
    name: str = ""
    scanner_type: ScannerType
    target: str = Field(..., min_length=1)
    options: dict = Field(default_factory=dict)
    frequency: ScanFrequency
    hour: int = Field(default=3, ge=0, le=23)
    minute: int = Field(default=0, ge=0, le=59)
    day_of_week: int | None = Field(default=None, ge=0, le=6, description="0=lunes .. 6=domingo, requerido si frequency='weekly'")

    @model_validator(mode="after")
    def _weekly_needs_day(self) -> "ScanScheduleCreate":
        if self.frequency == "weekly" and self.day_of_week is None:
            raise ValueError("day_of_week es requerido cuando frequency='weekly'")
        return self


class ScanScheduleUpdate(BaseModel):
    enabled: bool


class ScanScheduleOut(BaseModel):
    id: str
    name: str
    scanner_type: ScannerType
    target: str
    options: dict
    frequency: str
    hour: int
    minute: int
    day_of_week: int | None
    enabled: bool
    created_by: str
    created_at: datetime
    last_run_at: datetime | None
    last_status: str

    class Config:
        from_attributes = True


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
