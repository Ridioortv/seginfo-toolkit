"""Excepciones de riesgo (aceptar una vulnerabilidad por un tiempo, con aprobacion de otra persona)."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class RiskException(Base):
    __tablename__ = "risk_exceptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    vuln_id: Mapped[str] = mapped_column(String(36), index=True)
    vuln_title: Mapped[str] = mapped_column(String(500), default="")
    vuln_severity: Mapped[str] = mapped_column(String(10), default="")
    cve_id: Mapped[str] = mapped_column(String(30), default="")
    # pending | approved | rejected | withdrawn | revoked | expired | closed
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)
    justification: Mapped[str] = mapped_column(Text, default="")
    compensating_controls: Mapped[str] = mapped_column(Text, default="")
    requested_days: Mapped[int] = mapped_column(Integer, default=90)
    requested_by: Mapped[str] = mapped_column(String(255), default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    decided_by: Mapped[str] = mapped_column(String(255), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_reason: Mapped[str] = mapped_column(String(300), default="")
