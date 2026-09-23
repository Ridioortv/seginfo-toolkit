"""Business logic for auth-service: organizaciones (tenants), user auth,
SSO (OIDC), MFA, immutable audit log."""
import re
import secrets
import hashlib
import pyotp
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.security import hash_password, verify_password, create_access_token, create_refresh_token
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.models import User, Role, AuditLogEntry, Organization, SsoConfig


# --- Organizaciones (tenants) y SSO ---

_SLUG_RE = re.compile(r"[^a-z0-9-]+")


def slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.strip().lower()).strip("-")
    return slug or secrets.token_hex(4)


async def get_default_organization(db: AsyncSession) -> Organization:
    """La organizacion a la que se backfillean los usuarios que ya existian
    antes de que existiera multi-tenancy (ver migracion en main.py::lifespan)
    y, en un deploy on-prem de un solo cliente (el caso de uso original de
    esta plataforma, todavia el mas comun), la unica organizacion que va a
    existir nunca. Se crea perezosamente la primera vez que hace falta, y
    SIEMPRE con id=DEFAULT_ORGANIZATION_ID (no un uuid random): ese id es
    fijo y conocido de antemano por el resto de los microservicios (ver
    backend/shared/tenancy.py), que backfillean sus propias tablas viejas a
    esa misma organizacion sin tener que preguntarle a auth-service cual es."""
    result = await db.execute(select(Organization).where(Organization.slug == "default"))
    org = result.scalar_one_or_none()
    if org is None:
        org = Organization(id=DEFAULT_ORGANIZATION_ID, name="Default", slug="default")
        db.add(org)
        await db.flush()
    return org


async def create_organization(db: AsyncSession, name: str) -> Organization:
    slug = slugify(name)
    # Colision de slug (dos organizaciones con nombres que normalizan igual,
    # ej. "Acme Corp" y "ACME CORP!!") -- se le suma un sufijo random en vez
    # de fallar la creacion, porque el slug es solo cosmetico (la URL del
    # login SSO), no un identificador que alguien haya elegido a mano.
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none() is not None:
        slug = f"{slug}-{secrets.token_hex(3)}"
    org = Organization(name=name, slug=slug)
    db.add(org)
    await db.flush()
    await db.refresh(org)
    return org


async def list_organizations(db: AsyncSession) -> list[Organization]:
    result = await db.execute(select(Organization).order_by(Organization.created_at.asc()))
    return list(result.scalars().all())


async def get_organization_by_slug(db: AsyncSession, slug: str) -> Organization | None:
    result = await db.execute(select(Organization).where(Organization.slug == slug))
    return result.scalar_one_or_none()


async def get_organization_by_id(db: AsyncSession, org_id: str) -> Organization | None:
    return await db.get(Organization, org_id)


async def get_sso_config(db: AsyncSession, organization_id: str) -> SsoConfig | None:
    result = await db.execute(select(SsoConfig).where(SsoConfig.organization_id == organization_id))
    return result.scalar_one_or_none()


async def upsert_sso_config(
    db: AsyncSession, organization_id: str, issuer: str, client_id: str, client_secret: str,
    default_role: str, enabled: bool,
) -> SsoConfig:
    config = await get_sso_config(db, organization_id)
    if config is None:
        config = SsoConfig(organization_id=organization_id)
        db.add(config)
    config.issuer = issuer.rstrip("/")
    config.client_id = client_id
    config.client_secret = client_secret
    config.default_role = default_role
    config.enabled = enabled
    await db.flush()
    await db.refresh(config)
    return config


# --- Usuarios ---

async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.email == email)
    )
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id)
    )
    return result.scalar_one_or_none()


async def get_or_create_role(db: AsyncSession, name: str) -> Role:
    result = await db.execute(select(Role).where(Role.name == name))
    role = result.scalar_one_or_none()
    if role is None:
        role = Role(name=name, description=f"Rol {name}")
        db.add(role)
        await db.flush()
    return role


async def create_user(
    db: AsyncSession, email: str, password: str, full_name: str,
    organization_id: str, role_name: str = "analyst",
) -> User:
    """role_name solo lo pasa codigo interno de confianza (el bootstrap de
    admin, un futuro endpoint admin-only para crear usuarios). El endpoint
    publico /auth/register nunca lo expone -- ver comentario en schemas.py."""
    role = await get_or_create_role(db, role_name)
    user = User(
        email=email, hashed_password=hash_password(password), full_name=full_name,
        role_id=role.id, organization_id=organization_id,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def count_users(db: AsyncSession) -> int:
    result = await db.execute(select(func.count()).select_from(User))
    return result.scalar_one()


async def promote_first_user_to_admin_if_needed(db: AsyncSession) -> None:
    """Bootstrap: si ya hay usuarios pero ninguno es admin todavia (tipico
    en una base nueva, o en esta migrando desde antes de que existiera este
    chequeo), el usuario mas antiguo se asciende a admin automaticamente.
    Es idempotente -- una vez que existe un admin, no vuelve a tocar nada."""
    if await count_users(db) == 0:
        return
    admin_role = await get_or_create_role(db, "admin")
    result = await db.execute(select(func.count()).select_from(User).where(User.role_id == admin_role.id))
    if result.scalar_one() > 0:
        return
    result = await db.execute(select(User).order_by(User.created_at.asc()).limit(1))
    first_user = result.scalar_one_or_none()
    if first_user is not None:
        first_user.role_id = admin_role.id
        # El primer usuario de todo el sistema tambien queda como
        # administrador de la plataforma (puede crear otras
        # organizaciones) -- en un deploy on-prem de un solo cliente esto
        # no importa (nunca va a crear una segunda organizacion), pero en
        # un deploy multi-tenant real alguien tiene que poder hacerlo.
        first_user.is_platform_admin = True
        await db.flush()


async def backfill_users_without_organization(db: AsyncSession) -> None:
    """Migracion de datos (no de esquema -- eso ya lo hizo el ALTER TABLE en
    main.py::lifespan): cualquier usuario que exista de antes de que
    existiera multi-tenancy tiene organization_id NULL. Se los asigna a la
    organizacion "default" para que sigan pudiendo loguearse (un usuario sin
    organizacion no puede recibir un JWT valido, ver issue_tokens)."""
    result = await db.execute(select(User).where(User.organization_id.is_(None)))
    orphans = list(result.scalars().all())
    if not orphans:
        return
    default_org = await get_default_organization(db)
    for user in orphans:
        user.organization_id = default_org.id
    await db.flush()


async def get_or_create_google_user(db: AsyncSession, email: str, full_name: str) -> User:
    """Login/registro con Google: el token ya viene verificado por Google, asi
    que si el email no existe se crea la cuenta directamente (sin password,
    auth_provider='google'); si ya existe (se registro con password antes),
    simplemente se le permite entrar tambien por Google. Se le asigna la
    organizacion "default" -- este camino de login (personal, sin
    configuracion previa) no tiene forma de saber a que empresa pertenece
    quien entra, a diferencia del SSO empresarial (ver
    get_or_create_oidc_user) donde la organizacion la determina la URL."""
    user = await get_user_by_email(db, email)
    if user is not None:
        return user
    role = await get_or_create_role(db, "analyst")
    default_org = await get_default_organization(db)
    user = User(
        email=email, hashed_password=None, full_name=full_name, role_id=role.id,
        auth_provider="google", organization_id=default_org.id,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    user.role = role
    return user


async def get_or_create_oidc_user(db: AsyncSession, email: str, full_name: str, organization: Organization, default_role: str) -> User:
    """Login SSO empresarial: el id_token ya viene verificado (firma +
    issuer + audiencia, ver app/oidc.py) contra el proveedor configurado
    para ESTA organizacion especifica, asi que si el email no existe se
    crea la cuenta ya asociada a esa organizacion. A diferencia de Google
    (arriba), aca la organizacion nunca es ambigua: la determina la URL
    /auth/oidc/{slug}/... que arranco el flujo, no el dominio del email."""
    user = await get_user_by_email(db, email)
    if user is not None:
        return user
    role = await get_or_create_role(db, default_role)
    user = User(
        email=email, hashed_password=None, full_name=full_name, role_id=role.id,
        auth_provider="oidc", organization_id=organization.id,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    user.role = role
    return user


async def authenticate(db: AsyncSession, email: str, password: str, totp_code: str | None) -> User | None:
    user = await get_user_by_email(db, email)
    # user.hashed_password puede ser None para cuentas creadas solo por
    # Google -- no tienen password, asi que el login con email/password
    # simplemente falla en vez de romper contra passlib.
    if user is None or user.hashed_password is None or not verify_password(password, user.hashed_password):
        return None
    if user.mfa_enabled:
        if not totp_code or not pyotp.TOTP(user.mfa_secret).verify(totp_code, valid_window=1):
            return None
    return user


def issue_tokens(user: User, role_name: str) -> tuple[str, str]:
    return (
        create_access_token(user.id, role_name, user.organization_id, user.is_platform_admin),
        create_refresh_token(user.id),
    )


async def enroll_mfa(db: AsyncSession, user: User) -> tuple[str, str]:
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    await db.flush()
    otpauth_url = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="SentinelOps")
    return secret, otpauth_url


async def confirm_mfa(db: AsyncSession, user: User, totp_code: str) -> bool:
    if not user.mfa_secret or not pyotp.TOTP(user.mfa_secret).verify(totp_code, valid_window=1):
        return False
    user.mfa_enabled = True
    await db.flush()
    return True


async def record_audit_event(db: AsyncSession, actor_email: str, action: str, resource: str = "") -> AuditLogEntry:
    """Append-only audit log with a hash chain: each entry's hash depends on the
    previous entry's hash, so tampering with any past row breaks the chain."""
    result = await db.execute(select(AuditLogEntry).order_by(AuditLogEntry.timestamp.desc()).limit(1))
    last = result.scalar_one_or_none()
    prev_hash = last.hash if last else "0" * 64
    payload = f"{actor_email}|{action}|{resource}|{prev_hash}".encode()
    entry = AuditLogEntry(
        actor_email=actor_email,
        action=action,
        resource=resource,
        prev_hash=prev_hash,
        hash=hashlib.sha256(payload).hexdigest(),
    )
    db.add(entry)
    await db.flush()
    return entry
