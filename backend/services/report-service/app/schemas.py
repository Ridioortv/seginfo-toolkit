"""Pydantic schemas for report-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

ReportType = Literal["executive_summary", "vulnerabilities", "incidents", "attack_coverage"]


class ReportRequest(BaseModel):
    report_type: ReportType


class GeneratedReportOut(BaseModel):
    id: str
    report_type: str
    generated_by: str
    data: dict
    errors: list[str] = Field(default_factory=list)
    created_at: datetime

    class Config:
        from_attributes = True
