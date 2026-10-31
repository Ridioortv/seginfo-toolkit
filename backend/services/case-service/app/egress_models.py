"""Tablas de la prueba de soberania (ver backend/shared/egress.py). Son de la INSTALACION, no de una
organizacion: las salidas a internet las hace el sistema, no un cliente."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class EgressService(Base):
    """Ultimo informe de cada servicio: si esta en modo aislado y cuando hablo por ultima vez."""

    __tablename__ = "egress_services"

    service: Mapped[str] = mapped_column(String(60), primary_key=True)
    instance: Mapped[str] = mapped_column(String(120), default="")
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    allowlist: Mapped[str] = mapped_column(Text, default="[]")
    boot: Mapped[str] = mapped_column(String(40), default="")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class EgressDestination(Base):
    """Cada destino externo visto, por servicio. Los contadores se acumulan (los servicios informan diferencias)."""

    __tablename__ = "egress_destinations"
    __table_args__ = (UniqueConstraint("service", "host", "kind", name="uq_egress_dest"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    service: Mapped[str] = mapped_column(String(60), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="http")
    count: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[int] = mapped_column(Integer, default=0)
    purposes: Mapped[str] = mapped_column(Text, default="[]")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class EgressProbe(Base):
    """Cada prueba de conectividad hecha desde la red de TERO hacia internet."""

    __tablename__ = "egress_probes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(255), default="")
    reachable: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[str] = mapped_column(Text, default="[]")
