"""Tablas del riesgo de proveedores (por organizacion). Los cambios importantes quedan ademas en la cadena de custodia
(vendor.*); estas tablas guardan el estado actual."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Vendor(Base):
    __tablename__ = "vendors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255), default="")
    criticality: Mapped[str] = mapped_column(String(10), default="medium")  # critical | high | medium | low
    service_description: Mapped[str] = mapped_column(Text, default="")
    data_types: Mapped[list] = mapped_column(JSON, default=list)
    owner: Mapped[str] = mapped_column(String(255), default="")
    contact_email: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(12), default="active")  # active | offboarded
    contract_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class VendorAssessment(Base):
    """Un cuestionario enviado a un proveedor. El link lleva un token al azar; aca solo se guarda su SHA-256."""
    __tablename__ = "vendor_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    vendor_id: Mapped[str] = mapped_column(String(36), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(12), default="sent")  # sent | completed | cancelled
    template_version: Mapped[str] = mapped_column(String(20), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    respondent_name: Mapped[str] = mapped_column(String(255), default="")
    respondent_email: Mapped[str] = mapped_column(String(255), default="")
    answers: Mapped[str] = mapped_column(Text, default="{}")
    score_base: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_detail: Mapped[str] = mapped_column(Text, default="{}")
    answers_sha256: Mapped[str] = mapped_column(String(64), default="")


class VendorEvidence(Base):
    """Ficha de un documento de respaldo (certificacion, pentest, DPA...). El archivo lo guarda quien lo carga; aca van
    la ficha, el vencimiento y, si se quiere, la huella SHA-256 del archivo para poder demostrar que no cambio."""
    __tablename__ = "vendor_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    vendor_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(255))
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reference_url: Mapped[str] = mapped_column(String(500), default="")
    document_sha256: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    added_by: Mapped[str] = mapped_column(String(255), default="")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
