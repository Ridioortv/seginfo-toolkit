"""Modelos de la app "Gobernanza de codigo con IA" (coderepo-service).

Cinco piezas que se apoyan entre si:
  * CodeChange        -- procedencia: cada commit con su origen (humano / IA / mixto), herramienta,
                         modelo, prompt, lineas y hallazgos. Es el CONTADOR de modificaciones.
  * LedgerEntry       -- registro de auditoria encadenado (hash) y firmado (HMAC): nadie puede
                         editar ni borrar el historial sin que la verificacion lo detecte.
  * GovernancePolicy  -- politicas de uso de IA por equipo/zona del codigo, con modo "observar"
                         (solo mide) o "exigir" (bloquea).
  * GateRun           -- cada evaluacion de la compuerta de seguridad.
Los hallazgos de secretos (gitleaks) y de dependencias (trivy) siguen en app/models.py."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


ORIGINS = ("human", "ai", "mixed")
GATE_STATUSES = ("passed", "blocked", "observed_fail")
REVIEW_STATUSES = ("none", "approved", "rejected")


class CodeChange(Base):
    """Un commit/modificacion de codigo con su procedencia. Una fila por (repositorio, commit)."""

    __tablename__ = "gov_changes"
    __table_args__ = (UniqueConstraint("repo_target_id", "commit_sha", name="uq_gov_change_repo_sha"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    repo_target_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    commit_sha: Mapped[str] = mapped_column(String(64), index=True, default="")
    author_name: Mapped[str] = mapped_column(String(255), default="")
    author_email: Mapped[str] = mapped_column(String(255), default="")
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    message: Mapped[str] = mapped_column(String(500), default="")
    # human | ai | mixed
    origin: Mapped[str] = mapped_column(String(10), default="human", index=True)
    ai_tool: Mapped[str] = mapped_column(String(100), default="")
    ai_model: Mapped[str] = mapped_column(String(150), default="")
    # Resumen / referencia del prompt declarado (nunca el prompt completo si es sensible).
    prompt_ref: Mapped[str] = mapped_column(String(500), default="")
    # trailer (leido del commit) | declared (CI o persona) | default (sin senales: humano)
    detection: Mapped[str] = mapped_column(String(20), default="default")
    lines_added: Mapped[int] = mapped_column(Integer, default=0)
    lines_removed: Mapped[int] = mapped_column(Integer, default=0)
    files_changed: Mapped[int] = mapped_column(Integer, default=0)
    files_json: Mapped[str] = mapped_column(Text, default="[]")
    findings_json: Mapped[str] = mapped_column(Text, default="[]")
    review_status: Mapped[str] = mapped_column(String(10), default="none")
    review_count: Mapped[int] = mapped_column(Integer, default=0)
    reviewed_by: Mapped[str] = mapped_column(String(255), default="")
    # Correos de quienes aprobaron (sin repetir): las "revisiones exigidas" cuentan personas distintas.
    reviewers_json: Mapped[str] = mapped_column(Text, default="[]")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    gate_status: Mapped[str] = mapped_column(String(15), default="passed")
    gate_policy_name: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class LedgerEntry(Base):
    """Registro de auditoria append-only. Cada fila lleva el hash de la anterior (prev_hash) y una
    firma HMAC de su propio hash: ver app/ledger.py."""

    __tablename__ = "gov_ledger"
    __table_args__ = (UniqueConstraint("organization_id", "seq", name="uq_gov_ledger_org_seq"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="")
    subject: Mapped[str] = mapped_column(String(255), default="")
    payload: Mapped[str] = mapped_column(Text, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(64))


class GovernancePolicy(Base):
    __tablename__ = "gov_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    # None = todos los repositorios de la organizacion.
    repo_target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Zonas del codigo (prefijos de ruta separados por coma o salto de linea). Vacio = todo el repo.
    path_prefixes: Mapped[str] = mapped_column(String(1000), default="")
    # allowed | restricted (IA permitida pero con 1 revision humana minimo) | forbidden
    ai_policy: Mapped[str] = mapped_column(String(12), default="allowed")
    required_reviews: Mapped[int] = mapped_column(Integer, default=0)
    # none | critical | high | medium : desde que severidad un hallazgo frena el cambio
    block_on_severity: Mapped[str] = mapped_column(String(10), default="high")
    # observe (solo mide) | enforce (bloquea)
    mode: Mapped[str] = mapped_column(String(10), default="observe")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    updated_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class GateRun(Base):
    __tablename__ = "gov_gate_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    repo_target_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    change_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(15), default="passed")
    mode: Mapped[str] = mapped_column(String(10), default="observe")
    policy_name: Mapped[str] = mapped_column(String(255), default="")
    violations_json: Mapped[str] = mapped_column(Text, default="[]")
    # scan | ci | review | manual
    trigger: Mapped[str] = mapped_column(String(10), default="scan")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
