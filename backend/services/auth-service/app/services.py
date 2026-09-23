"""Business logic for auth-service: user auth, MFA, immutable audit log."""
import hashlib
import pyotp
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.security import hash_password, verify_password, create_access_token, create_refresh_token
from app.models import User, Role, AuditLogEntry


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


async def create_user(db: AsyncSession, email: str, password: str, full_name: str, role_name: str = "analyst") -> User:
    """role_name solo lo pasa codigo interno de confianza (el bootstrap de
    admin, un futuro endpoint admin-only para crear usuarios). El endpoint
    publico /auth/register nunca lo expone -- ver comentario en schemas.py."""
    role = await get_or_create_role(db, role_name)
    user = User(email=email, hashed_password=hash_password(password), full_name=full_name, role_id=role.id)
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
        await db.flush()


async def get_or_create_google_user(db: AsyncSession, email: str, full_name: str) -> User:
    """Login/registro con Google: el token ya viene verificado por Google, asi
    que si el email no existe se crea la cuenta directamente (sin password,
    auth_provider='google'); si ya existe (se registro con password antes),
    simplemente se le permite entrar tambien por Google."""
    user = await get_user_by_email(db, email)
    if user is not None:
        return user
    role = await get_or_create_role(db, "analyst")
    user = User(email=email, hashed_password=None, full_name=full_name, role_id=role.id, auth_provider="google")
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
    return create_access_token(user.id, role_name), create_refresh_token(user.id)


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
