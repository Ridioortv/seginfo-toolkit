"""Vinculo entre algo de TERO (una vulnerabilidad o un caso) y su ticket en Jira o ServiceNow."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TicketLink(Base):
    __tablename__ = "integration_ticket_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    connector_id: Mapped[str] = mapped_column(String(36), index=True)
    provider: Mapped[str] = mapped_column(String(20), default="jira")
    subject_type: Mapped[str] = mapped_column(String(20), index=True)   # vulnerability | case
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    subject_title: Mapped[str] = mapped_column(String(500), default="")
    external_key: Mapped[str] = mapped_column(String(100), default="", index=True)
    external_id: Mapped[str] = mapped_column(String(100), default="")
    external_url: Mapped[str] = mapped_column(String(600), default="")
    # open | resolved | closed_no_fix | simulated
    state: Mapped[str] = mapped_column(String(20), default="open", index=True)
    external_status: Mapped[str] = mapped_column(String(100), default="")
    applied: Mapped[bool] = mapped_column(Boolean, default=False)   # ya se aplico el cierre del lado de TERO
    applied_note: Mapped[str] = mapped_column(Text, default="")
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
