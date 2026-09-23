"""Pydantic schemas for scan-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from app.models import ScannerType, ScanStatus
from app.target_validation import validate_target

ScanFrequency = Literal["daily", "weekly"]


class ScanJobCreate(BaseModel):
    name: str = ""
    scanner_type: ScannerType
    target: str = Field(..., min_length=1, description="Host, CIDR o referencia de imagen segun el scanner")
    asset_id: str | None = None
    options: dict = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)


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

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

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


# --- Agentes de escaneo remoto (ver app/models.py: ScanAgent, AgentScanJob) ---

class ScanAgentCreate(BaseModel):
    name: str = Field(..., min_length=1)


class ScanAgentOut(BaseModel):
    id: str
    name: str
    created_by: str
    created_at: datetime
    last_seen_at: datetime | None

    class Config:
        from_attributes = True


class ScanAgentCreated(ScanAgentOut):
    """Se devuelve SOLO en la respuesta de creacion: es la unica vez que el
    api_key en texto plano existe en algun lado fuera de la maquina del
    agente -- el servidor solo guarda su hash (ver ScanAgent.key_hash)."""

    api_key: str


AgentJobStatus = Literal["pending", "assigned", "completed", "failed"]


class AgentScanJobCreate(BaseModel):
    agent_id: str = Field(..., min_length=1)
    name: str = ""
    # Por ahora el agente remoto (remote-agent/agent.py) solo sabe correr
    # nmap -- se restringe aca para no crear jobs que ningun agente pueda
    # ejecutar. Ampliar cuando el agente soporte mas scanners.
    scanner_type: Literal["nmap"] = "nmap"
    target: str = Field(..., min_length=1)
    options: dict = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)


class AgentScanJobOut(BaseModel):
    id: str
    agent_id: str
    name: str
    scanner_type: str
    target: str
    options: dict
    status: AgentJobStatus
    findings: list[dict]
    error_message: str
    created_by: str
    created_at: datetime
    assigned_at: datetime | None
    finished_at: datetime | None

    class Config:
        from_attributes = True


class AgentPollJob(BaseModel):
    """Lo minimo que necesita el agente para ejecutar -- no se le manda la
    fila completa de AgentScanJob (created_by, timestamps, etc no le
    sirven de nada)."""

    id: str
    scanner_type: str
    target: str
    options: dict


class AgentPollResponse(BaseModel):
    jobs: list[AgentPollJob]


class AgentResultSubmit(BaseModel):
    status: Literal["completed", "failed"]
    findings: list[dict] = Field(default_factory=list)
    raw_output: str = ""
    error_message: str = ""
