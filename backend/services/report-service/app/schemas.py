"""Pydantic schemas for report-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, model_validator

ReportType = Literal["executive_summary", "vulnerabilities", "incidents", "attack_coverage"]
ReportFrequency = Literal["daily", "weekly"]


class ReportRequest(BaseModel):
    report_type: ReportType


class ReportScheduleCreate(BaseModel):
    report_type: ReportType
    notification_channel_id: str = Field(..., min_length=1, description="Un canal tipo 'email' de notification-service")
    frequency: ReportFrequency
    hour: int = Field(default=8, ge=0, le=23)
    minute: int = Field(default=0, ge=0, le=59)
    day_of_week: int | None = Field(default=None, ge=0, le=6, description="0=lunes .. 6=domingo, requerido si frequency='weekly'")

    @model_validator(mode="after")
    def _weekly_needs_day(self) -> "ReportScheduleCreate":
        if self.frequency == "weekly" and self.day_of_week is None:
            raise ValueError("day_of_week es requerido cuando frequency='weekly'")
        return self


class ReportScheduleUpdate(BaseModel):
    enabled: bool


class ReportScheduleOut(BaseModel):
    id: str
    report_type: str
    notification_channel_id: str
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


class GeneratedReportOut(BaseModel):
    id: str
    report_type: str
    generated_by: str
    data: dict
    errors: list[str] = Field(default_factory=list)
    created_at: datetime

    class Config:
        from_attributes = True
