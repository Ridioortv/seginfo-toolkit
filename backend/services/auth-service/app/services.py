"""Business logic for auth-service: user auth, MFA, immutable audit log."""
import hashlib
import pyotp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.security import hash_password, verify_password, create_access_token, create_refresh_token
from app.models import User, Role, AuditLogEntry


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_or_create_role(db: AsyncSession, name: str) -> Role:
    result = await db.execute(select(Role).where(Role.name == name))
    role = result.scalar_one_or_none()
    if role is None:
        role = Role(name=name, description=f"Rol {name}")
        db.add(role)
        await db.flush()
    return role


async def create_user(db: AsyncSession, email: str, password: str, full_name: str, role_name: str) -> User:
    role = await get_or_create_role(db, role_name)
    user = User(email=email, hashed_password=hash_password(password), full_name=full_name, role_id=role.id)
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def authenticate(db: AsyncSession, email: str, password: str, totp_code: str | None) -> User | None:
    user = await get_user_by_email(db, email)
    if user is None or not verify_password(password, user.hashed_password):
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
