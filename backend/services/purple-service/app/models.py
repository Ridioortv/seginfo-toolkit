"""SQLAlchemy models for purple-service: ejercicios purple team (un
conjunto de tecnicas MITRE ATT&CK DECLARADAS como puestas a prueba -- nunca
ejecutadas por esta plataforma, ver docs/architecture.md 'Fuera de
alcance') y el resultado de cobertura calculado contra las reglas Sigma de
siem-service."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, Text
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
