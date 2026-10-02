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
        # (ver target_validation.reject_dangerous_network_target). El resto
        # (nmap/nuclei/openvas) SI corre dentro de la red docker de la
        # plataforma, asi que su target se valida contra ese denylist.
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
    # El agente remoto (remote-agent/agent.py) ahora sabe correr los cuatro
    # escaneres. nmap/trivy/nuclei son binarios sueltos que el agente corre
    # localmente; openvas requiere ademas un stack GVM en la maquina del
    # agente (si no lo tiene, el agente reporta un error claro en vez de
    # colgarse). Ver remote-agent/agent.py.
    scanner_type: Literal["nmap", "trivy", "nuclei", "openvas"] = "nmap"
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


# --- Activacion de OpenVAS desde la UI (ver GET/POST /openvas/*, app/
# scanners/openvas.py::probe_connection) ---
# OpenVAS esta apagado por defecto (ver docker-compose.yml, profile
# "openvas") y este proceso NO tiene acceso al socket de Docker: no puede
# levantar los contenedores de GVM el mismo. Lo que si puede hacer es
# probar la conexion GMP con credenciales ya en pie (contenedores ya
# levantados por openvas/Encender-OpenVAS.ps1) y, si funciona, aplicarlas
# en memoria para no exigir un reinicio del contenedor.

class OpenvasActivateRequest(BaseModel):
    gvm_user: str = Field(..., min_length=1)
    gvm_password: str = Field(..., min_length=1)
    gvm_socket_path: str = Field(default="", description="Vacio usa el default /run/gvmd/gvmd.sock")


class OpenvasStatusOut(BaseModel):
    configured: bool
    ready: bool
    detail: str


# --- Activacion AUTOMATICA de OpenVAS (ver POST/GET /openvas/auto-activate*
# en main.py) -- a diferencia de OpenvasActivateRequest de arriba (que solo
# prueba credenciales contra un gvmd YA levantado a mano), esta llama al
# servicio openvas-orchestrator (unico con acceso al socket de Docker, ver
# openvas-orchestrator/main.py) para que levante el profile "openvas" el
# mismo, cree/actualice el usuario GVM, y guarde las credenciales en .env
# -- sin que el operador corra ningun script de PowerShell.

class OpenvasAutoActivateRequest(BaseModel):
    gvm_user: str = Field(default="admin", min_length=1)
    gvm_password: str = Field(default="", description="Vacio = el orquestador genera una password aleatoria")
    gvm_socket_path: str = Field(default="", description="Vacio usa el default /run/gvmd/gvmd.sock")


class OpenvasProgressOut(BaseModel):
    running: bool
    # Contenedores arriba + usuario GVM creado/actualizado + .env escrito
    # -- por el orquestador. NO implica todavia que scan-service haya
    # confirmado la conexion GMP (eso es `ready`, ver abajo).
    provisioned: bool
    # True solo cuando, ADEMAS de `provisioned`, main.py::openvas_auto_activate_progress
    # ya probo la conexion GMP con exito (misma funcion que usa el
    # /openvas/activate manual) y aplico las credenciales en memoria.
    ready: bool
    phase: str
    percent: int
    detail: str
    error: str | None = None
    gvm_user: str | None = None
    gvm_password: str | None = None


# --- Dashboard de OpenVAS (ver app/gvm_manage.py y GET/POST/DELETE
# /openvas/configs, /port-lists, /report-formats, /credentials, /targets,
# /tasks, /reports/* en main.py) -- una vez que OpenVAS esta activo
# (OpenvasProgressOut.ready / OpenvasStatusOut.ready), esto es lo que deja
# elegir tipo de escaneo, credenciales para escaneo autenticado, targets
# reusables y exportar reportes completos, en vez de que el driver elija
# todo solo (ver _CONFIG_NAME_PREFERENCES etc. en app/scanners/openvas.py,
# que sigue siendo el fallback cuando no se especifica nada de esto).

class GvmEntityOut(BaseModel):
    """Config de escaneo / scanner / formato de reporte tal como los
    devuelve gvmd -- solo id+nombre, alcanza para poblar un <select/>."""

    id: str
    name: str


class GvmCredentialCreate(BaseModel):
    name: str = Field(..., min_length=1)
    login: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class GvmCredentialOut(BaseModel):
    id: str
    name: str
    login: str
    credential_type: str


class GvmTargetCreate(BaseModel):
    name: str = Field(..., min_length=1)
    hosts: str = Field(..., min_length=1, description="Host, rango o CIDR -- mismo formato que ScanJobCreate.target")
    port_list_id: str = Field(..., min_length=1)
    ssh_credential_id: str | None = None
    smb_credential_id: str | None = None

    @field_validator("hosts")
    @classmethod
    def _validate_hosts(cls, v: str) -> str:
        v = validate_target(v)
        # Siempre target de red (gvmd/ospd-openvas tambien corren dentro de
        # la red docker de la plataforma) -- a diferencia de ScanJobCreate,
        # aca no hay scanner_type que pueda ser trivy, asi que se aplica
        # sin condicion.
        reject_dangerous_network_target(v)
        return v


class GvmTargetOut(BaseModel):
    id: str
    name: str
    hosts: str
    port_list_id: str | None
    ssh_credential_id: str | None
    smb_credential_id: str | None


class GvmTaskOut(BaseModel):
    id: str
    name: str
    status: str
    progress: int
    target_id: str | None
    last_report_id: str | None
