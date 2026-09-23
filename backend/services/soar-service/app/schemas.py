"""Pydantic schemas for soar-service."""
from datetime import datetime
from pydantic import BaseModel, Field
from app.models import RunStatus, CaseStatus


class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    min_severity: str = "high"
    rule_tags: list[str] = Field(default_factory=list)
    steps: list[dict] = Field(default_factory=list)
    is_enabled: bool = True


class PlaybookUpdate(BaseModel):
    description: str | None = None
    min_severity: str | None = None
    rule_tags: list[str] | None = None
    steps: list[dict] | None = None
    is_enabled: bool | None = None


class PlaybookOut(BaseModel):
    id: str
    name: str
    description: str
    min_severity: str
    rule_tags: list[str]
    steps: list[dict]
    is_enabled: bool
    source_file: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PlaybookRunOut(BaseModel):
    id: str
    playbook_id: str
    playbook_name: str
    alert_id: str | None
    status: RunStatus
    steps_log: list[dict]
    triggered_by: str
    created_at: datetime
    finished_at: datetime | None

    class Config:
        from_attributes = True


class TriggerRequest(BaseModel):
    """Lo que envia siem-service cuando dispara una alerta (ver
    siem-service/app/services.py _notify_soar)."""

    alert_id: str
    rule_name: str = ""
    severity: str = "medium"
    event: dict = Field(default_factory=dict)
    # Opcional -- lo manda siem-service (su propio org_id, ya resuelto del
    # JWT de quien ingesto el log). Si falta, se asume la organizacion
    # default (ver backend/shared/tenancy.py).
    organization_id: str | None = None


class TriggerResponse(BaseModel):
    playbooks_matched: int
    runs: list[PlaybookRunOut]


class ManualRunRequest(BaseModel):
    alert_id: str | None = None
    event: dict = Field(default_factory=dict)


class PendingCaseOut(BaseModel):
    id: str
    title: str
    description: str
    priority: str
    alert_id: str | None
    playbook_run_id: str | None
    status: CaseStatus
    created_at: datetime

    class Config:
        from_attributes = True
