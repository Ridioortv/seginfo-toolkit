"""Foto diaria de los numeros del tablero ejecutivo (para dibujar la tendencia sin recalcular el pasado)."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ExecutiveSnapshot(Base):
    __tablename__ = "executive_snapshots"
    __table_args__ = (UniqueConstraint("organization_id", "day", name="uq_executive_snapshot_day"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    day: Mapped[str] = mapped_column(String(10), index=True)  # AAAA-MM-DD (UTC)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    data: Mapped[str] = mapped_column(Text, default="{}")
