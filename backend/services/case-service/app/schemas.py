"""Pydantic schemas for case-service."""
from datetime import datetime
from pydantic import BaseModel, Field
from app.models import CasePriority, CaseStatus


class CaseCreate(BaseModel):
    title: str
    description: str = ""
    priority: CasePriority = CasePriority.medium
    assignee: str = ""
    alert_id: str | None = None
    source: str = "manual"


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    priority: CasePriority | None = None
    status: CaseStatus | None = None
    assignee: str | None = None


class TimelineEntryOut(BaseModel):
    id: str
    actor: str
    action: str
    notes: str
    created_at: datetime

    class Config:
        from_attributes = True


class CaseOut(BaseModel):
    id: str
    title: str
    description: str
    priority: CasePriority
    status: CaseStatus
    assignee: str
    alert_id: str | None
    source: str
    sla_due_at: datetime | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    timeline: list[TimelineEntryOut] = Field(default_factory=list)

    class Config:
        from_attributes = True


class TimelineEntryCreate(BaseModel):
    action: str
    notes: str = ""


class ImportResult(BaseModel):
    imported: int
    skipped: int
