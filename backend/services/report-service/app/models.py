"""SQLAlchemy models for report-service: historial de reportes generados
(agregaciones de datos de otros servicios, nunca datos inventados -- si un
servicio fuente no responde, esa seccion queda vacia y se registra en
`errors`)."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ReportSchedule(Base):
    """Una regla de reporte recurrente: genera el reporte y lo manda por
    email (via notification-service, canal tipo 'email') como PDF
    adjunto. report-service la corre con su propio scheduler en proceso
    (APScheduler, ver app/main.py) -- mismo patron que scan-service."""

    __tablename__ = "report_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    notification_channel_id: Mapped[str] = mapped_column(String(36), nullable=False)
    frequency: Mapped[str] = mapped_column(String(20), nullable=False)  # daily | weekly
    hour: Mapped[int] = mapped_column(Integer, default=8)
    minute: Mapped[int] = mapped_column(Integer, default=0)
    day_of_week: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0=lunes .. 6=domingo (solo weekly)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(500), default="")


class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(255), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
