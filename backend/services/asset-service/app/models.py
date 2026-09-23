"""SQLAlchemy models for asset-service: CMDB de activos (hosts, servicios, tags)."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Enum as SAEnum, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base
import enum


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AssetCriticality(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AssetEnvironment(str, enum.Enum):
    production = "production"
    staging = "staging"
    development = "development"
    other = "other"


class Asset(Base):
    """Registro de inventario (CMDB). Es la fuente de verdad de que activos
    existen y cuales pueden ser objetivo de un escaneo (ver scan-service)."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Nullable a nivel de columna SQL a proposito: instalaciones existentes
    # migran con un ALTER TABLE que no puede rellenar esto atomicamente para
    # filas viejas (ver lifespan en main.py, que backfillea a
    # DEFAULT_ORGANIZATION_ID). A nivel de aplicacion, todo activo nuevo
    # SIEMPRE recibe una organization_id (ver services.create_asset).
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True, default="")
    ip_address: Mapped[str] = mapped_column(String(45), index=True, default="")
    mac_address: Mapped[str] = mapped_column(String(17), default="")
    os_name: Mapped[str] = mapped_column(String(100), default="")
    os_version: Mapped[str] = mapped_column(String(100), default="")
    environment: Mapped[AssetEnvironment] = mapped_column(
        SAEnum(AssetEnvironment, native_enum=False), default=AssetEnvironment.production
    )
    criticality: Mapped[AssetCriticality] = mapped_column(
        SAEnum(AssetCriticality, native_enum=False), default=AssetCriticality.medium
    )
    owner: Mapped[str] = mapped_column(String(255), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(default=True)
    notes: Mapped[str] = mapped_column(String(2000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class AssetGroup(Base):
    """Agrupacion logica de activos (ej: 'Servidores web produccion'), usada
    por scan-service como alcance de escaneo y por vuln-service para reportes."""

    __tablename__ = "asset_groups"
    # name era unique=True a nivel global antes de multi-tenancy; ahora es
    # unique por organizacion (dos clientes distintos SI pueden llamar a un
    # grupo "Servidores web produccion" cada uno). La migracion de la
    # constraint vieja a esta se hace a mano en main.py::lifespan porque
    # create_all no altera constraints de tablas ya existentes.
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_asset_groups_org_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), default="")
    asset_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
