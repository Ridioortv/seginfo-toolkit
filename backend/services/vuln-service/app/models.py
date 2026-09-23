"""SQLAlchemy models for vuln-service: normaliza hallazgos de scan-service
en registros de vulnerabilidad, los enriquece con CVSS/EPSS/CISA KEV y
soporta el workflow de triage (confirmar, marcar falso positivo, aceptar
riesgo, marcar remediado)."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Enum as SAEnum, Float, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base
import enum


def _now() -> datetime:
    return datetime.now(timezone.utc)


class VulnSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class VulnStatus(str, enum.Enum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    remediated = "remediated"


class Vulnerability(Base):
    """Un hallazgo normalizado. Puede o no tener CVE asociado (p.ej. un
    puerto abierto detectado por nmap no tiene CVE, pero un paquete
    desactualizado detectado por trivy si). El `priority_score` es lo que
    ordena la cola de triage y se recalcula en cada enriquecimiento."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    cve_id: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[VulnSeverity] = mapped_column(SAEnum(VulnSeverity, native_enum=False), default=VulnSeverity.info)

    source_scanner: Mapped[str] = mapped_column(String(50), default="")
    scan_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    package: Mapped[str] = mapped_column(String(255), default="")
    installed_version: Mapped[str] = mapped_column(String(100), default="")
    fixed_version: Mapped[str] = mapped_column(String(100), default="")
    port: Mapped[int | None] = mapped_column(nullable=True)
    service: Mapped[str] = mapped_column(String(100), default="")

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(100), default="")
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[str] = mapped_column(String(20), default="")
    priority_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    status: Mapped[VulnStatus] = mapped_column(SAEnum(VulnStatus, native_enum=False), default=VulnStatus.open)
    triage_note: Mapped[str] = mapped_column(Text, default="")
    triaged_by: Mapped[str] = mapped_column(String(255), default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
