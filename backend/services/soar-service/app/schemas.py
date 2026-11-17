"""Pydantic schemas for soar-service."""
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from app.models import RunStatus, CaseStatus


SEVERITIES = ("info", "low", "medium", "high", "critical")


def _check_min_severity(v: str | None) -> str | None:
    """Una severidad desconocida (ej. "ultra") tenia rango 0 en el motor, asi
    que el playbook disparaba con CUALQUIER alerta (fallaba abierto)."""
    if v is None:
        return None
    v = v.strip().lower()
    if v not in SEVERITIES:
        raise ValueError("min_severity debe ser una de: " + ", ".join(SEVERITIES))
    return v


def _check_steps(steps: list[dict] | None) -> list[dict] | None:
    """Cada paso necesita una 'action' conocida; antes se guardaba cualquier
    cosa y el error recien aparecia al ejecutar el playbook."""
    if steps is None:
        return None
    from app.actions import ACTIONS
    for i, step in enumerate(steps, 1):
        action = step.get("action") if isinstance(step, dict) else None
        if action not in ACTIONS:
            raise ValueError(f"Paso {i}: accion desconocida {action!r}. Disponibles: " + ", ".join(sorted(ACTIONS)))
        if "params" in step and not isinstance(step["params"], dict):
            raise ValueError(f"Paso {i}: 'params' debe ser un objeto")
    return steps


class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    min_severity: str = "high"
    rule_tags: list[str] = Field(default_factory=list)
    steps: list[dict] = Field(default_factory=list)
    is_enabled: bool = True

    @field_validator("min_severity")
    @classmethod
    def _v_sev(cls, v):
        return _check_min_severity(v)

    @field_validator("steps")
    @classmethod
    def _v_steps(cls, v):
        return _check_steps(v)


class PlaybookUpdate(BaseModel):
    description: str | None = None
    min_severity: str | None = None
    rule_tags: list[str] | None = None
    steps: list[dict] | None = None
    is_enabled: bool | None = None

    @field_validator("min_severity")
    @classmethod
    def _v_sev(cls, v):
        return _check_min_severity(v)

    @field_validator("steps")
    @classmethod
    def _v_steps(cls, v):
        return _check_steps(v)


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
    # Tags de la regla Sigma que genero la alerta (los manda siem-service).
    rule_tags: list[str] = Field(default_factory=list)


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
