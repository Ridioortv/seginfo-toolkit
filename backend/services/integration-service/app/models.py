"""SQLAlchemy models for integration-service: conectores de contencion
(firewall/EDR) configurados por el operador y el log de cada accion
ejecutada o simulada a traves de ellos. Los conectores son genericos
(webhook REST) -- no incluyen SDKs propietarios de ningun vendor
especifico, y por defecto (INTEGRATION_DRY_RUN=true) nunca llaman a la
URL configurada, solo registran la intencion (mismo patron que
SOAR_DRY_RUN en soar-service)."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)  # firewall | edr
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # ej. {'base_url': ..., 'header_name': 'X-Api-Key'}
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IntegrationActionLog(Base):
    __tablename__ = "integration_action_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    connector_id: Mapped[str] = mapped_column(String(36), default="")
    action: Mapped[str] = mapped_column(String(50), nullable=False)  # block_ip | isolate_host
    target: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(20), default="simulated")  # executed | failed | simulated
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
