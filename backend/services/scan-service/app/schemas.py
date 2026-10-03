"""Pydantic schemas for scan-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from app.models import ScannerType, ScanStatus
from app.target_validation import validate_target, reject_dangerous_network_target

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

    @model_validator(mode="after")
    def _reject_dangerous_network_target(self) -> "ScanJobCreate":
        # trivy escanea una imagen/filesystem, no un host de red -- un
        # target "postgres:16" ahi es una referencia de imagen legitima y
        # comunisima, no el nombre del contenedor postgres de la plataforma
        # (ver target_validation.reject_dangerous_network_target). nuclei SI
        # corre dentro de la red docker de la plataforma, asi que su target
        # se valida contra ese denylist.
        if self.scanner_type != ScannerType.trivy:
            reject_dangerous_network_target(self.target)
        return self


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
    # Si se especifica, la regla la ejecuta ESTE agente remoto en vez de
    # correr dentro del contenedor (ver ScanSchedule.agent_id en models.py
    # y run_scheduled_scan en services.py). agent_api_key se exige SOLO en
    # este request -- igual que al lanzar un escaneo remoto manual, ver
    # AgentScanJobCreate.api_key -- para probar que quien crea la regla
    # conoce la key del agente elegido; se valida en main.py::create_schedule
    # y NUNCA se persiste (la regla solo guarda agent_id).
    agent_id: str | None = Field(default=None, min_length=1)
    agent_api_key: str | None = Field(default=None, min_length=1)

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

    @model_validator(mode="after")
    def _weekly_needs_day(self) -> "ScanScheduleCreate":
        if self.frequency == "weekly" and self.day_of_week is None:
            raise ValueError("day_of_week es requerido cuando frequency='weekly'")
        return self

    @model_validator(mode="after")
    def _agent_needs_key(self) -> "ScanScheduleCreate":
        if self.agent_id and not self.agent_api_key:
            raise ValueError("agent_api_key es requerido cuando se especifica agent_id")
        return self

    @model_validator(mode="after")
    def _reject_dangerous_network_target(self) -> "ScanScheduleCreate":
        # Mismo criterio que ScanJobCreate: nunca para trivy (referencia de
        # imagen, no host). Ademas, nunca cuando agent_id esta seteado --
        # ese caso lo ejecuta un agente remoto FUERA de la red docker de la
        # plataforma (en la LAN real del cliente), asi que el denylist de
        # nombres de servicio internos no aplica (ver AgentScanJobCreate).
        if self.scanner_type != ScannerType.trivy and not self.agent_id:
            reject_dangerous_network_target(self.target)
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
    agent_id: str | None
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
    packages: list[dict]
    error_message: str
    created_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    class Config:
        from_attributes = True


# --- Inventario de imagenes/paquetes (dashboard de trivy, ver
# app/services.py::get_image_inventory) ---

class ImageInventoryItem(BaseModel):
    target: str
    scan_job_id: str
    scanned_at: datetime | None
    mode: str
    package_count: int
    vulnerability_count: int
    vulnerabilities_by_severity: dict[str, int]
    packages: list[dict]


# --- Agentes de escaneo remoto (ver app/models.py: ScanAgent, AgentScanJob) ---

class ScanAgentCreate(BaseModel):
    name: str = Field(..., min_length=1)


class ScanAgentOut(BaseModel):
    id: str
    name: str
    created_by: str
    created_at: datetime
    last_seen_at: datetime | None
    # true para los agentes bootstrap (Agente Docker/Agente LAN, ver
    # services.is_protected_agent) -- la UI no debe ofrecer borrarlos.
    is_protected: bool = False
    # Solo se llena para agentes bootstrap (ver services.resolve_bootstrap_api_key):
    # es la MISMA key que ya esta en el .env del operador, asi que mostrarla
    # de nuevo aca no es una fuga nueva -- sin esto, no hay forma de lanzar
    # un escaneo remoto con el Agente Docker/Agente LAN desde la UI, porque
    # nunca se registraron ahi (se auto-crean al arrancar scan-service).
    bootstrap_api_key: str | None = None

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
    # El agente remoto (remote-agent/agent.py) sabe correr trivy y nuclei --
    # binarios sueltos que corre localmente en la maquina del agente. Ver
    # remote-agent/agent.py.
    scanner_type: Literal["trivy", "nuclei"] = "nuclei"
    target: str = Field(..., min_length=1)
    options: dict = Field(default_factory=dict)
    # Al LANZAR un escaneo remoto desde la UI se exige tambien la api key del
    # agente elegido (ademas del JWT del usuario): se valida contra el hash
    # guardado de ese agente (ver main.py::create_agent_scan y
    # services.agent_key_matches). NUNCA se persiste -- solo se usa para
    # validar en el momento de crear el job.
    api_key: str = Field(..., min_length=1, description="Api key del agente elegido")

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
