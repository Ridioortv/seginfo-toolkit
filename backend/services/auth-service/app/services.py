"""Business logic for auth-service: organizaciones (tenants), user auth,
SSO (OIDC), MFA, immutable audit log."""
import logging
import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
import base64
import io
import pyotp
import segno
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.security import hash_password, verify_password, create_access_token, create_refresh_token
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from backend.shared.crypto import encrypt_secret
from backend.shared import license_check
from app.models import User, Role, AuditLogEntry, Organization, SsoConfig

logger = logging.getLogger("auth-service")

# Cuanto tiempo se sigue confiando en el ultimo check-in exitoso contra el
# servidor central de licencias si los siguientes intentos fallan (red
# caida, servidor central abajo, etc). Pasado esto, is_org_active()
# bloquea aunque el cache local (subscription_expires_at) diga que todavia
# falta -- cierra el hueco de "cortar la salida a internet para siempre y
# quedarse con el ultimo estado 'valido' cacheado indefinidamente". Ver
# backend/shared/license_check.py para el resto del razonamiento.
LICENSE_GRACE_DAYS = 3


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


def is_org_active(org: Organization) -> bool:
    """True si la organizacion puede seguir emitiendo tokens (login/
    refresh/Google/SSO). Bloqueo total (no downgrade a solo-lectura) --
    decision explicita del operador: al dia 30 sin renovar, se corta
    todo. Se llama en CADA login/refresh/Google/callback SSO (ver
    main.py) -- como los access token duran poco (15 min por defecto),
    esto alcanza para un bloqueo practicamente inmediato sin tener que
    agregar una verificacion cruzada contra auth-service en cada request
    de los otros 10 microservicios."""
    now = datetime.now(timezone.utc)
    if org.subscription_expires_at <= now:
        return False
    if license_check.is_configured() and org.license_last_checked_at is not None:
        if now - org.license_last_checked_at > timedelta(days=LICENSE_GRACE_DAYS):
            return False
    return True


async def extend_subscription(db: AsyncSession, organization_id: str, days: int) -> Organization | None:
    """Renovacion manual -- lo que usa el operador hoy hasta que el
    servidor central de licencias este conectado a PayPal (ver
    PUT/POST /auth/organizations/{id}/subscription en main.py). Extiende
    desde el vencimiento ACTUAL (o desde ahora si ya venció), nunca desde
    'ahora' a secas -- mismo criterio que licensing-server/app/main.py::extend_client,
    para que renovar un poco antes no le haga perder dias al cliente."""
    org = await get_organization_by_id(db, organization_id)
    if org is None:
        return None
    now = datetime.now(timezone.utc)
    base = max(org.subscription_expires_at, now)
    org.subscription_expires_at = base + timedelta(days=days)
    await db.flush()
    await db.refresh(org)
    return org


async def refresh_license_from_central_server(db: AsyncSession, organization_id: str) -> None:
    """Se llama periodicamente (tarea de fondo en main.py::lifespan) y
    tambien se puede llamar a mano. No hace nada si LICENSE_SERVER_URL no
    esta configurado (instalaciones que gestionan todo via
    extend_subscription a mano). Cualquier fallo (red, firma invalida,
    etc) se loguea y se ignora -- NO se toca subscription_expires_at ni
    license_last_checked_at en ese caso, para que is_org_active() siga
    confiando en el ultimo check-in bueno (dentro de su ventana de
    gracia) en vez de en un fallo transitorio."""
    if not license_check.is_configured():
        return
    org = await get_organization_by_id(db, organization_id)
    if org is None:
        return
    try:
        valid, valid_until = await license_check.check_license()
    except license_check.LicenseCheckError as exc:
        logger.warning("no se pudo confirmar la licencia contra el servidor central: %s", exc)
        return
    org.license_last_checked_at = datetime.now(timezone.utc)
    if valid and valid_until is not None:
        org.subscription_expires_at = valid_until
    elif not valid:
        # El servidor central dice explicitamente que esta licencia no es
        # valida (no solo "no pude confirmar") -- se corta ya, no se
        # espera a que expire subscription_expires_at por las suyas.
        org.subscription_expires_at = datetime.now(timezone.utc)
    await db.flush()


async def get_organization_by_slug(db: AsyncSession, slug: str) -> Organization | None:
    result = await db.execute(select(Organization).where(Organization.slug == slug))
    return result.scalar_one_or_none()


async def get_organization_by_id(db: AsyncSession, org_id: str) -> Organization | None:
    return await db.get(Organization, org_id)


async def get_sso_config(db: AsyncSession, organization_id: str) -> SsoConfig | None:
    # OJO: esto devuelve el objeto ORM tal cual esta en la base -- si
    # config.enabled es True, config.client_secret esta CIFRADO. No
    # descifrar aca (mutando el atributo) porque un `await db.commit()`
    # posterior en el mismo request (ej. en el callback de OIDC) volveria
    # a escribir el texto plano en la base, destruyendo el cifrado. El
    # descifrado se hace solo en el punto de uso real, ver
    # app/oidc.py::exchange_code.
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
    # client_secret se guarda cifrado (Fernet, ver backend/shared/crypto.py)
    # -- antes se guardaba en texto plano en la base, asi que quien tuviera
    # acceso de lectura a la base (un backup filtrado, una inyeccion SQL en
    # cualquier otro endpoint, un admin de infraestructura del cliente)
    # podia leer el client_secret de Azure AD/Okta/etc de esa organizacion.
    config.client_secret = encrypt_secret(client_secret)
    config.default_role = default_role
    config.enabled = enabled
    await db.flush()
    await db.refresh(config)
    return config


# --- Usuarios ---

async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    # Sin distinguir mayusculas: antes "Ana@x.com" y "ana@x.com" eran cuentas distintas. Si por datos
    # viejos hubiera dos filas, se usa la mas antigua (nunca un error 500 por "mas de una fila").
    result = await db.execute(
        select(User).options(selectinload(User.role))
        .where(func.lower(User.email) == (email or "").strip().lower())
        .order_by(User.created_at).limit(1)
    )
    return result.scalars().first()


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id)
    )
    return result.scalar_one_or_none()


# Roles que un administrador puede asignar al crear/editar una cuenta:
#   admin        -> todo, incluida la administracion de usuarios, SSO y pagos
#   soc_manager  -> opera todo el SOC (escaneos, casos, SOAR, reportes)
#   analyst      -> ejecuta tareas operativas (escaneos, triage, casos)
#   viewer       -> SOLO LECTURA: ve el sistema pero no ejecuta ni modifica nada
# Cada servicio decide con require_role(...) que roles pueden ejecutar cada
# accion; "viewer" no esta en ninguna lista de escritura, asi que queda de solo
# lectura sin tocar nada mas.
ASSIGNABLE_ROLES = ("admin", "soc_manager", "analyst", "viewer")
# Rol de quien entra SIN que un admin lo haya dado de alta (auto-registro o
# Google desconocido): minimo privilegio. Nunca se puede auto-elegir.
SELF_SERVICE_ROLE = "viewer"


def self_registration_allowed() -> bool:
    """ALLOW_SELF_REGISTRATION=false cierra el alta abierta (el instalador lo
    deja asi en un cliente: solo entran cuentas creadas por un admin). El PRIMER
    usuario de una instalacion siempre puede registrarse (es el admin inicial)."""
    return os.getenv("ALLOW_SELF_REGISTRATION", "true").strip().lower() not in ("0", "false", "no", "off")


async def list_users_in_org(db: AsyncSession, org_id: str) -> list[User]:
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.organization_id == org_id).order_by(User.created_at.asc())
    )
    return list(result.scalars().all())


async def get_user_in_org(db: AsyncSession, org_id: str, user_id: str) -> User | None:
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id, User.organization_id == org_id)
    )
    return result.scalar_one_or_none()


async def count_active_admins(db: AsyncSession, org_id: str) -> int:
    admin_role = await get_or_create_role(db, "admin")
    result = await db.execute(
        select(func.count()).select_from(User).where(
            User.organization_id == org_id, User.role_id == admin_role.id, User.is_active.is_(True)
        )
    )
    return result.scalar_one()


FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.com.ar", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "aol.com", "gmx.com", "yandex.com", "mail.com", "zoho.com",
})


def _email_domain(email: str) -> str:
    return (email or "").rsplit("@", 1)[-1].strip().lower()


def freemail_invites_allowed() -> bool:
    return os.getenv("ALLOW_FREEMAIL_INVITES", "false").strip().lower() in {"1", "true", "yes"}


async def invite_email_error(db: AsyncSession, org_id: str, email: str, *, caller_is_platform_admin: bool) -> str | None:
    """Devuelve un mensaje de error si un admin de organizacion NO puede dar de
    alta ese email, o None si puede.

    Por que existe: users.email es unico a nivel global y el login por Google
    resuelve la cuenta solo por email. Sin esta regla, el admin de una
    organizacion podia dar de alta el email de una persona AJENA y, cuando esa
    persona entraba con Google, quedaba dentro del tenant del atacante (y la
    organizacion real de esa persona ya no podia darla de alta).

    Regla: en una instalacion con varias organizaciones, el admin solo puede
    dar de alta emails del MISMO dominio que los usuarios que su organizacion
    ya tiene; los dominios de correo gratuito (gmail, outlook...) no prueban
    pertenencia a una empresa, asi que quedan reservados a un platform_admin
    (o a ALLOW_FREEMAIL_INVITES=true en instalaciones de una sola empresa).
    Una instalacion con una sola organizacion no tiene tenants contra quien
    capturar, asi que no se restringe."""
    if caller_is_platform_admin:
        return None
    org_count = (await db.execute(select(func.count()).select_from(Organization))).scalar_one()
    if org_count <= 1:
        return None
    domain = _email_domain(email)
    if domain in FREE_MAIL_DOMAINS:
        if freemail_invites_allowed():
            return None
        return (
            "No se pueden dar de alta emails de correo gratuito (gmail, outlook...) en una instalacion con varias "
            "organizaciones: no prueban que la persona sea de tu empresa. Usa el email corporativo."
        )
    result = await db.execute(
        select(User.email).where(User.organization_id == org_id, User.is_active.is_(True))
    )
    if any(_email_domain(e) == domain for (e,) in result.all()):
        return None
    return (
        f"El dominio @{domain} no coincide con el de los usuarios de tu organizacion. "
        "Pedile a un administrador de plataforma que de de alta ese email."
    )


async def admin_create_user(
    db: AsyncSession, org_id: str, email: str, full_name: str, role_name: str, password: str | None,
) -> User:
    """Alta hecha por un administrador. Con password -> cuenta local (email +
    contrasena, y MFA que el usuario activa en su primer ingreso). Sin password
    -> cuenta que entra con Google: queda pre-aprobada con ESTE rol, y la
    persona solo tiene que iniciar sesion con ese email de Google."""
    role = await get_or_create_role(db, role_name)
    user = User(
        email=email,
        hashed_password=hash_password(password) if password else None,
        full_name=full_name,
        role_id=role.id,
        organization_id=org_id,
        auth_provider="local" if password else "google",
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    user.role = role
    return user


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
    organization_id: str, role_name: str = SELF_SERVICE_ROLE,
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
        first_user.role = admin_role  # que el objeto en memoria ya refleje el rol nuevo (lo usa issue_tokens)
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


async def _adopt_local_account_for_federated_login(db: AsyncSession, user: User, provider: str) -> None:
    """Si el email ya tenia una cuenta local con password (registro abierto, sin
    verificar que el email sea de quien se registro) y ahora entra el DUEÑO
    verificado del email por Google/SSO, la cuenta pasa a ese proveedor y se
    borran el password y el MFA locales. Sin esto, quien registro primero el
    email de otra persona conservaba su password y seguia entrando a la misma
    cuenta (pre-claim)."""
    if user.is_platform_admin:
        return
    if user.auth_provider == "local" and user.hashed_password is not None:
        user.hashed_password = None
        user.mfa_enabled = False
        user.mfa_secret = None
        user.auth_provider = provider
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
        await _adopt_local_account_for_federated_login(db, user, "google")
        return user
    role = await get_or_create_role(db, SELF_SERVICE_ROLE)
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
        # Solo se adopta si la cuenta ya es de ESTA organizacion: el IdP de la
        # org B no puede tocar (ni borrarle el password) a un usuario de la org A.
        if user.organization_id == organization.id:
            await _adopt_local_account_for_federated_login(db, user, "oidc")
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
    if not user.is_active:
        # Cuenta desactivada por un admin: mismo mensaje generico que un login
        # fallido (no revela que la cuenta existe).
        return None
    if user.mfa_enabled:
        if not totp_code or not pyotp.TOTP(user.mfa_secret).verify(totp_code, valid_window=1):
            return None
    return user


def issue_tokens(user: User, role_name: str) -> tuple[str, str]:
    return (
        create_access_token(user.id, role_name, user.organization_id, user.is_platform_admin, email=user.email),
        create_refresh_token(user.id),
    )


def verify_current_totp(user: User, totp_code: str | None) -> bool:
    """True si totp_code es un codigo TOTP valido para el secret MFA
    ACTUAL de este usuario (valid_window=1, mismo criterio que
    authenticate() y confirm_mfa()). Funcion pura (nada de I/O, solo
    pyotp) -- usada por mfa_enroll para exigir prueba de que quien pide
    reemplazar el secret todavia controla el dispositivo ya enrolado."""
    if not user.mfa_secret or not totp_code:
        return False
    return pyotp.TOTP(user.mfa_secret).verify(totp_code, valid_window=1)


async def enroll_mfa(db: AsyncSession, user: User) -> tuple[str, str]:
    # OJO: esto pisa user.mfa_secret sin condicion -- si el usuario YA
    # tiene mfa_enabled=True, quien llama a esta funcion (app/main.py::
    # mfa_enroll) tiene que haber verificado antes, con
    # verify_current_totp(), que quien pide el re-enrolamiento controla
    # el secret ACTUAL. Sin eso, cualquiera con un access_token robado
    # (no hace falta conocer el TOTP real) podia reemplazar en silencio
    # el secret de MFA de otro usuario y apropiarse del segundo factor.
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    await db.flush()
    otpauth_url = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="TERO Security")
    return secret, otpauth_url


def mfa_qr_data_uri(otpauth_url: str) -> str:
    """QR (SVG, data URI) del otpauth:// para escanear con Google Authenticator,
    Authy, Microsoft Authenticator, 1Password, Bitwarden, etc. Se genera en el
    servidor: el secreto nunca sale a un servicio de QR de terceros."""
    # OJO: svg_inline() NO incluye xmlns; como <img src="data:..."> el navegador no
    # dibuja un SVG sin xmlns (queda un cuadro blanco). save(..., svgns=True) lo agrega.
    buf = io.BytesIO()
    segno.make(otpauth_url, error="m").save(
        buf, kind="svg", scale=6, border=3, dark="#000000", light="#ffffff", xmldecl=False, svgns=True
    )
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


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
