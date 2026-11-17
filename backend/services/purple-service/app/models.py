"""SQLAlchemy models for purple-service: ejercicios purple team (un
conjunto de tecnicas MITRE ATT&CK DECLARADAS como puestas a prueba -- nunca
ejecutadas por esta plataforma, ver docs/architecture.md 'Fuera de
alcance') y el resultado de cobertura calculado contra las reglas Sigma de
siem-service."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PurpleExercise(Base):
    """Un ejercicio: nombre + lista de technique_id que el equipo red/purple
    declara haber puesto a prueba (importados como datos, por ejemplo desde
    el reporte de una herramienta externa de simulacion de adversarios --
    esta plataforma no ejecuta nada, solo analiza la cobertura declarada)."""

    __tablename__ = "purple_exercises"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    declared_technique_ids: Mapped[list] = mapped_column(JSON, default=list)
    last_coverage_result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class PurpleDrill(Base):
    """Un simulacro de respuesta a incidentes (ver app/drills.py): un evento sintetico rotulado en el SIEM y los tiempos
    medidos hasta que una persona reconoce y cierra la alerta. No ejecuta ninguna tecnica de ataque."""

    __tablename__ = "purple_drills"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    scenario: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="running", index=True)
    started_by: Mapped[str] = mapped_column(String(255), default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    injected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detected: Mapped[bool] = mapped_column(Boolean, default=False)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    alert_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acked_by: Mapped[str] = mapped_column(String(255), default="")
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_by: Mapped[str] = mapped_column(String(255), default="")
    close_note_chars: Mapped[int] = mapped_column(Integer, default=0)
    playbooks_would_respond: Mapped[int | None] = mapped_column(Integer, nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(String(255), default="")
