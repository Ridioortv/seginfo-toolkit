"""Tablas del cumplimiento con evidencia viva (por organizacion).

  * ComplianceDeclaration: lo que una PERSONA declara de un control que TERO no puede comprobar (copias de respaldo,
    capacitacion, contratos...). Con nota, quien, cuando y hasta cuando vale. Solo la ultima vigente cuenta; el
    historial completo esta en la cadena de custodia (compliance.declaration).
  * ComplianceSnapshot: foto del estado (puntaje y resultado de cada control) para ver la evolucion en el tiempo."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class ComplianceDeclaration(Base):
    __tablename__ = "compliance_declarations"
    __table_args__ = (UniqueConstraint("organization_id", "control_id", name="uq_compliance_decl"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    control_id: Mapped[str] = mapped_column(String(20), index=True)
    answer: Mapped[str] = mapped_column(String(10))  # yes | partial | no
    note: Mapped[str] = mapped_column(Text, default="")
    declared_by: Mapped[str] = mapped_column(String(255), default="")
    declared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ComplianceSnapshot(Base):
    __tablename__ = "compliance_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(255), default="")
    score_verified: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_total: Mapped[float | None] = mapped_column(Float, nullable=True)
    counts: Mapped[str] = mapped_column(Text, default="{}")
    controls: Mapped[str] = mapped_column(Text, default="{}")  # {control_id: estado}
    body_sha256: Mapped[str] = mapped_column(String(64), default="")
    total_controls: Mapped[int] = mapped_column(Integer, default=0)
