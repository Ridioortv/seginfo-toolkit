"""SQLAlchemy models for soar-service: playbooks de respuesta (definidos en
YAML, ver playbooks/*.yaml y app/playbook_loader.py) y el historial de
corridas. Las acciones que un playbook ejecuta (bloquear IP, aislar host,
crear caso) corren en modo DRY-RUN por defecto -- ver app/actions/base.py --
porque integration-service (Fase 5) es quien todavia no existe para proveer
conectores reales contra firewall/EDR; el diseño ya deja el lugar para
enchufarlos sin cambiar el modelo de playbooks."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, Boolean, Enum as SAEnum, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base
import enum


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RunStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class CaseStatus(str, enum.Enum):
    pending = "pending"
    synced = "synced"


class Playbook(Base):
    """Un playbook: condicion de disparo (severidad minima de alerta, y
    opcionalmente tags de regla) + lista ordenada de pasos (accion + params)."""

    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    min_severity: Mapped[str] = mapped_column(String(20), default="high")
    rule_tags: Mapped[list] = mapped_column(JSON, default=list)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source_file: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class PlaybookRun(Base):
    """Una ejecucion de un playbook contra una alerta concreta."""

    __tablename__ = "playbook_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id: Mapped[str] = mapped_column(String(36), index=True)
    playbook_name: Mapped[str] = mapped_column(String(255), default="")
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    status: Mapped[RunStatus] = mapped_column(SAEnum(RunStatus, native_enum=False), default=RunStatus.pending)
    steps_log: Mapped[list] = mapped_column(JSON, default=list)
    triggered_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PendingCase(Base):
    """Cuando un playbook ejecuta la accion 'create_case' y case-service
    (Fase 4) todavia no existe o no responde, la solicitud de caso se guarda
    aca para que case-service la pueda importar cuando este disponible."""

    __tablename__ = "pending_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(20), default="medium")
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    playbook_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[CaseStatus] = mapped_column(SAEnum(CaseStatus, native_enum=False), default=CaseStatus.pending)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
