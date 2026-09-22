"""SQLAlchemy models for case-service: incidentes (estilo ITSM/kanban) y su
timeline de eventos/acciones."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Enum as SAEnum, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.shared.database import Base
import enum


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CasePriority(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class CaseStatus(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    resolved = "resolved"
    closed = "closed"


# SLA por prioridad, en horas desde la apertura del caso.
SLA_HOURS_BY_PRIORITY = {
    CasePriority.critical: 4,
    CasePriority.high: 8,
    CasePriority.medium: 24,
    CasePriority.low: 72,
}


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[CasePriority] = mapped_column(SAEnum(CasePriority, native_enum=False), default=CasePriority.medium)
    status: Mapped[CaseStatus] = mapped_column(SAEnum(CaseStatus, native_enum=False), default=CaseStatus.open)
    assignee: Mapped[str] = mapped_column(String(255), default="")
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(50), default="manual")  # manual | soar-import
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    timeline: Mapped[list["CaseTimelineEntry"]] = relationship(back_populates="case", order_by="CaseTimelineEntry.created_at")


class CaseTimelineEntry(Base):
    __tablename__ = "case_timeline_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(100))
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    case: Mapped["Case"] = relationship(back_populates="timeline")
