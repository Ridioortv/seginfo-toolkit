"""Pydantic schemas for vuln-service."""
from datetime import datetime
from pydantic import BaseModel, Field
from app.models import VulnSeverity, VulnStatus


class FindingIn(BaseModel):
    """Espejo laxo de scan-service.schemas.Finding: se acepta como dict
    flexible para no acoplar los dos servicios a un mismo schema estricto."""

    title: str
    description: str = ""
    severity: str = "info"
    cve_id: str | None = None
    port: int | None = None
    service: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None


class IngestRequest(BaseModel):
    scan_job_id: str | None = None
    asset_id: str | None = None
    scanner_type: str = ""
    # Opcional (no viene de un JWT -- este endpoint es servicio-a-servicio y
    # no requiere uno, ver main.py::ingest) para no romper a un caller viejo
    # que todavia no lo manda; si falta, ingest_findings lo trata como la
    # organizacion default (ver backend/shared/tenancy.py).
    organization_id: str | None = None
    findings: list[FindingIn] = Field(default_factory=list)


class IngestResponse(BaseModel):
    created: int
    updated: int


class TriageRequest(BaseModel):
    status: VulnStatus
    note: str = ""


class VulnerabilityOut(BaseModel):
    id: str
    cve_id: str | None
    title: str
    description: str
    severity: VulnSeverity
    source_scanner: str
    scan_job_id: str | None
    asset_id: str | None
    package: str
    installed_version: str
    fixed_version: str
    port: int | None
    service: str
    cvss_score: float | None
    cvss_vector: str
    epss_score: float | None
    is_kev: bool
    kev_date_added: str
    priority_score: float
    last_enriched_at: datetime | None
    status: VulnStatus
    triage_note: str
    triaged_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityStatsOut(BaseModel):
    total: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    kev_count: int
    avg_priority_score: float
