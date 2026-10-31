"""Tabla de la cadena de custodia (ver backend/shared/custody_core.py para el diseno).

Solo se agrega: ninguna funcion de este servicio modifica ni borra filas de custody_entries."""
import uuid

from sqlalchemy import Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


class CustodyEntry(Base):
    __tablename__ = "custody_entries"
    __table_args__ = (UniqueConstraint("organization_id", "seq", name="uq_custody_org_seq"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    ts: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), index=True, default="")
    actor: Mapped[str] = mapped_column(String(255), default="")
    source: Mapped[str] = mapped_column(String(50), default="")
    subject_type: Mapped[str] = mapped_column(String(30), default="")
    subject_id: Mapped[str] = mapped_column(String(100), index=True, default="")
    # JSON canonico de la lista de referencias cruzadas (ej. ["alert:...", "case:..."]).
    refs: Mapped[str] = mapped_column(Text, default="[]")
    # JSON canonico del detalle del evento; payload_sha256 es lo que entra en la firma.
    payload: Mapped[str] = mapped_column(Text, default="{}")
    payload_sha256: Mapped[str] = mapped_column(String(64), default="")
    leaf: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="")
    signature: Mapped[str] = mapped_column(String(128), default="")
