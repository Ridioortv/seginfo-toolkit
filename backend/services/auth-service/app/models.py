"""SQLAlchemy models for auth-service: organizations (tenants), users,
roles, SSO config, audit log."""
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.shared.database import Base

# Duracion de cada periodo de suscripcion (ver Organization.subscription_expires_at
# y app/services.py::is_org_active) -- el modelo de negocio es "$250 USD
# cada 30 dias, bloqueo total si no se renueva" (decision del operador).
SUBSCRIPTION_PERIOD_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _default_subscription_expiry() -> datetime:
    return _now() + timedelta(days=SUBSCRIPTION_PERIOD_DAYS)


class Organization(Base):
    """Un tenant. Cada usuario pertenece a exactamente una organizacion, y el
    id de esta se propaga como claim 'org_id' en el JWT (ver
    backend/shared/security.py) para que el resto de los microservicios
    puedan filtrar sus propias tablas por tenant sin volver a golpear a
    auth-service en cada request. `slug` es lo que aparece en la URL del
    login SSO (/auth/oidc/{slug}/login) -- nunca se expone el id interno ahi
    para no filtrar UUIDs en URLs que la gente puede compartir/bookmarkear."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # --- Suscripcion / licencia (ver app/services.py::is_org_active) ---
    # Toda organizacion nueva arranca con SUBSCRIPTION_PERIOD_DAYS (30) dias
    # de plataforma funcional desde el momento en que se crea -- "las
    # empresas pueden tener el software funcional desde el dia 1" (decision
    # del operador). Pasada esa fecha sin renovar, is_org_active() corta el
    # login/refresh de TODA la organizacion (bloqueo total, tambien decision
    # del operador -- no un downgrade a solo-lectura). Renovar (hoy, a mano,
    # via PUT /auth/organizations/{id}/subscription; mas adelante via el
    # servidor central de licencias, ver backend/shared/license_check.py)
    # simplemente empuja esta fecha para adelante.
    subscription_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_default_subscription_expiry, nullable=False
    )
    # Ultima vez que este servicio confirmo la suscripcion contra el
    # servidor central de licencias (solo se usa si LICENSE_SERVER_URL esta
    # configurado -- ver backend/shared/license_check.py). None significa
    # "todavia no se pudo confirmar ni una vez" (instalacion recien creada,
    # o el servidor central nunca respondio) -- is_org_active() NO bloquea
    # solo por esto (evita trabar una instalacion nueva por un problema de
    # red transitorio), pero SI bloquea si ya hubo una confirmacion exitosa
    # y luego pasaron mas de LICENSE_GRACE_DAYS sin poder repetirla -- eso
    # cierra el hueco de "cortar la salida a internet para siempre y
    # congelar el ultimo estado 'valido' cacheado".
    license_last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    sso_config: Mapped["SsoConfig | None"] = relationship(back_populates="organization", uselist=False)


class SsoConfig(Base):
    """Configuracion de SSO empresarial (OIDC) de UNA organizacion. Se separa
    de Organization (en vez de columnas sueltas ahi) porque no toda org la
    tiene configurada, y asi el 99% de las filas de Organization no cargan
    un client_secret potencialmente vacio/basura. Solo OIDC por ahora (no
    SAML) -- ver docs/runbook.md, seccion SSO, para el motivo."""

    __tablename__ = "sso_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), unique=True, nullable=False)
    # Issuer del proveedor OIDC (ej. "https://login.microsoftonline.com/<tenant>/v2.0"
    # para Azure AD/Entra ID). El discovery document se resuelve como
    # f"{issuer}/.well-known/openid-configuration" en tiempo de request (ver
    # app/oidc.py) -- no se guardan los endpoints resueltos porque el
    # proveedor los puede rotar.
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # Se guarda cifrado (Fernet, ver backend/shared/crypto.py -- claveado por
    # ENCRYPTION_KEY) y nunca se devuelve en ningun response (ver
    # schemas.SsoConfigOut). Se descifra solo en el punto de uso real
    # (app/oidc.py::exchange_code), nunca mutando este objeto ORM.
    client_secret: Mapped[str] = mapped_column(String(500), nullable=False)
    default_role: Mapped[str] = mapped_column(String(50), default="analyst")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    organization: Mapped["Organization"] = relationship(back_populates="sso_config")


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # unique=True (no compuesto con organization_id) a proposito: el email
    # sigue siendo el identificador de login global, exactamente como antes
    # de que existiera multi-tenancy -- dos organizaciones NO pueden tener
    # cada una un usuario con el mismo email. Simplifica /auth/login (no
    # hace falta que el usuario indique su organizacion aparte del email) y
    # evita el caso raro de una persona con la misma casilla en dos tenants
    # distintos, que de todos modos no aplica al modelo de negocio actual
    # (una empresa = un dominio de email = una organizacion).
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    auth_provider: Mapped[str] = mapped_column(String(20), default="local")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Aparte del rol (permisos), esta bandera es la unica cosa que puede
    # crear organizaciones nuevas o ver el listado de todas -- ver
    # dependencies.require_platform_admin. Deliberadamente NO es un "role"
    # mas: mezclar "administra su propia empresa" con "administra la
    # plataforma entera (todas las empresas)" en el mismo campo `role` iba a
    # ser una fuente segura de bugs de aislamiento entre tenants.
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"))
    role: Mapped["Role"] = relationship(back_populates="users")

    # Nullable a nivel de columna SQL a proposito (instalaciones existentes
    # migran con un ALTER TABLE que no puede rellenar esto atomicamente para
    # filas viejas en el mismo paso -- ver el lifespan de main.py, que crea
    # una organizacion "default" y hace el backfill ahi mismo). A nivel de
    # aplicacion, todo usuario nuevo SIEMPRE recibe una organization_id.
    organization_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    organization: Mapped["Organization | None"] = relationship(back_populates="users")


class AuditLogEntry(Base):
    """Append-only audit trail. Integrity is enforced at the application layer
    via a running hash chain (prev_hash -> hash) computed in services.py."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_email: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(255), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64))
