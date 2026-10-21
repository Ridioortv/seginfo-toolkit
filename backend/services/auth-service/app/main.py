"""auth-service entrypoint: identidad, organizaciones (tenants), JWT
issuance, MFA (TOTP), SSO empresarial (OIDC), RBAC."""
import asyncio
import os
import secrets
import re
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import urlencode
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from jwt import PyJWTError as JWTError
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.rate_limit import check_rate_limit
from backend.shared.security import decode_token, create_token
from backend.shared import license_check
from app.schemas import (
    UserCreate,
    UserOut,
    LoginRequest,
    TokenPair,
    MfaEnrollRequest,
    MfaEnrollResponse,
    MfaStatusResponse,
    UserAdminCreate,
    UserAdminOut,
    UserAdminUpdate,
    MfaVerifyRequest,
    GoogleAuthRequest,
    RefreshRequest,
    OrganizationCreate,
    OrganizationOut,
    SsoConfigIn,
    SsoConfigOut,
    SubscriptionExtendRequest,
    SubscriptionCancelOut,
    SubscriptionPayLinkOut,
    PaymentProvidersOut,
    SubscriptionPayLinkRequest,
    SubscriptionHistoryOut,
)
from app.dependencies import (
    get_current_claims, require_role, require_platform_admin, require_org_admin_or_platform_admin,
    require_service_token,
)
from app import services, oidc

logger = configure_logging("auth-service")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
# A donde se redirige al navegador despues de un login SSO exitoso (con los
# tokens en el fragmento de la URL, ver /auth/oidc/{slug}/callback). El
# frontend tiene que tener una ruta que los lea de ahi -- ver
# frontend/src/pages/SsoCallback.tsx.
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
login_attempts_total = Counter("auth_login_attempts_total", "Login attempts", ["outcome"])
LICENSE_CHECK_INTERVAL_HOURS = float(os.getenv("LICENSE_CHECK_INTERVAL_HOURS", "6"))


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _license_recheck_allowed(org_id: str) -> bool:
    """Como mucho un re-chequeo de licencia por organizacion cada 20 segundos
    desde el login bloqueado (el rate limit falla abierto si Redis no esta)."""
    try:
        await _enforce_rate_limit(f"license_recheck:{org_id}", limit=1, window_seconds=20)
    except HTTPException:
        return False
    return True


async def _reject_if_org_inactive(db: AsyncSession, org, actor_email: str) -> None:
    """402 (Payment Required) si la organizacion de este usuario no tiene
    la suscripcion al dia -- ver services.is_org_active() para el
    criterio exacto. Se llama en los 4 caminos que emiten tokens
    (login, Google, SSO, refresh); bloqueo total por decision del
    operador, no un downgrade a solo-lectura.

    A quien llega hasta aca ya se le verificaron sus credenciales (esta
    funcion se llama DESPUES de authenticate()/Google/SSO, nunca
    antes) -- por eso alcanza esa confianza para, ademas de bloquearlo,
    ofrecerle de una un link de pago (PayPal y/o Mercado Pago) generado al vuelo
    contra el servidor central de licencias, con actor_email como
    payer_email. El campo "detail" del 402 pasa a ser un objeto (no un
    string plano) para que el frontend pueda mostrar un boton "Pagar
    membresia" en vez de solo un cartel de error -- ver Login.tsx."""
    if services.is_org_active(org):
        return
    # Antes de bloquear, volver a consultar al servidor central: si el cliente
    # acaba de pagar (desde este mismo 402 o desde la pasarela), el webhook ya
    # extendio la licencia alla pero esta instalacion todavia no se entero
    # (el chequeo periodico corre cada LICENSE_CHECK_INTERVAL_HOURS). Sin esto
    # quedaba bloqueado varias horas despues de pagar, sin forma de refrescar
    # (el boton "Actualizar estado" exige estar logueado). Limitado por
    # organizacion para que un login repetido no golpee al servidor central.
    if license_check.is_configured() and await _license_recheck_allowed(org.id):
        await services.refresh_license_from_central_server(db, org.id)
        await db.commit()
        await db.refresh(org)
        if services.is_org_active(org):
            return
    login_attempts_total.labels(outcome="failure").inc()
    await services.record_audit_event(db, actor_email, "auth.login.blocked_subscription", org.id)
    await db.commit()

    # Un link por pasarela disponible (PayPal y/o Mercado Pago): el cliente
    # elige. payment_url (el de PayPal si hay, si no el primero) se mantiene
    # por compatibilidad con frontends anteriores.
    payment_urls: dict[str, str] = {}
    if license_check.is_configured():
        payment_urls = await license_check.get_payment_links(actor_email)
    payment_url = payment_urls.get("paypal") or next(iter(payment_urls.values()), None)

    message = "La suscripcion de esta organizacion no esta al dia."
    if payment_url:
        message += " Paga la membresia para recuperar el acceso."
    else:
        message += " Contacta al administrador de la plataforma para renovarla."

    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={"message": message, "payment_url": payment_url, "payment_urls": payment_urls},
    )


async def _license_check_loop() -> None:
    """Tarea de fondo: cada LICENSE_CHECK_INTERVAL_HOURS horas, refresca
    subscription_expires_at de TODAS las organizaciones contra el
    servidor central de licencias (ver backend/shared/license_check.py).
    No hace nada (ni loguea) si LICENSE_SERVER_URL no esta configurado --
    instalaciones que gestionan la suscripcion solo a mano via
    /auth/organizations/{id}/subscription/extend."""
    if not license_check.is_configured():
        return
    while True:
        try:
            async with SessionLocal() as session:
                orgs = await services.list_organizations(session)
                for org in orgs:
                    await services.refresh_license_from_central_server(session, org.id)
                await session.commit()
        except Exception:
            logger.exception("fallo inesperado en el ciclo de chequeo de licencia")
        await asyncio.sleep(LICENSE_CHECK_INTERVAL_HOURS * 3600)


async def _enforce_rate_limit(key: str, limit: int, window_seconds: int = 300) -> None:
    """429 si se supero el limite -- ver backend/shared/rate_limit.py.
    window_seconds=300 (5 min) por defecto en todos los usos de este
    modulo: alcanza para frenar fuerza bruta sostenida sin molestar a un
    usuario real que se equivoca la contraseña un par de veces."""
    if not await check_rate_limit(key, limit, window_seconds):
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos. Espera unos minutos antes de volver a intentar.",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migracion liviana para bases ya existentes (creadas antes de que
        # existiera el login con Google): agrega auth_provider si falta y
        # permite password nulo para cuentas que solo entran por Google.
        # create_all no altera tablas ya creadas, por eso el ALTER a mano.
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20) NOT NULL DEFAULT 'local'"
        ))
        await conn.execute(text(
            "ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL"
        ))
        # Idem para multi-tenancy: create_all crea las tablas organizations
        # y sso_configs (son nuevas), pero la tabla users ya existia en
        # cualquier instalacion previa a esto, asi que sus columnas nuevas
        # necesitan el mismo ALTER a mano. organization_id se backfillea
        # aparte, mas abajo (no puede ir en el mismo ALTER porque todavia
        # no existe la organizacion "default" a la que asignarselo).
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36) REFERENCES organizations(id)"
        ))
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE"
        ))
        # Suscripcion/licencia (ver app/models.py::Organization): las
        # organizaciones creadas antes de este cambio no tienen estas
        # columnas -- se agregan con un default de "30 dias desde ahora"
        # (mismo criterio que Organization.subscription_expires_at para
        # una fila nueva) en vez de dejarlas NULL, para no bloquear de
        # golpe a nadie que ya estaba usando la plataforma el dia que
        # esto se despliega.
        await conn.execute(text(
            "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS subscription_expires_at "
            "TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')"
        ))
        await conn.execute(text(
            "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS license_last_checked_at TIMESTAMPTZ"
        ))
    async with SessionLocal() as session:
        await services.promote_first_user_to_admin_if_needed(session)
        await services.backfill_users_without_organization(session)
        await session.commit()
    license_task = asyncio.create_task(_license_check_loop())
    logger.info("auth-service iniciado", extra={"license_server_configured": license_check.is_configured()})
    yield
    license_task.cancel()


app = FastAPI(title="TERO Security Auth Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "auth-service"}


@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    """Auto-registro publico: siempre crea el usuario como "analyst" en la
    organizacion "default" (el auto-registro abierto no tiene forma segura
    de saber a que EMPRESA pertenece quien se registra -- para clientes que
    necesitan su propia organizacion separada, un platform_admin usa
    POST /auth/organizations, que crea la empresa y su primer admin en un
    solo paso). Si es el primer usuario que existe en toda la base, el
    lifespan lo asciende a admin (y platform_admin) automaticamente la
    proxima vez que arranque el servicio (o ya lo hizo si esto es lo
    primero que corre)."""
    existing = await services.get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="El email ya esta registrado")
    if not services.self_registration_allowed() and await services.count_users(db) > 0:
        # El alta abierta esta cerrada en esta instalacion: las cuentas las crea
        # un administrador (pantalla "Usuarios"). El primer usuario siempre puede.
        raise HTTPException(
            status_code=403,
            detail="El registro abierto esta desactivado. Pidele a un administrador que cree tu cuenta.",
        )
    default_org = await services.get_default_organization(db)
    # Rol de menor privilegio ("viewer", solo lectura): quien se registra solo NUNCA elige su rol.
    # El primer usuario de la instalacion se asciende a admin mas abajo.
    user = await services.create_user(db, payload.email, payload.password, payload.full_name, default_org.id)
    await services.promote_first_user_to_admin_if_needed(db)
    await services.record_audit_event(db, payload.email, "user.register")
    await db.commit()
    # Recargar con el rol ya resuelto (create_user no lo trae eager-loaded,
    # y promote_first_user_to_admin_if_needed puede haberlo cambiado).
    user = await services.get_user_by_email(db, payload.email)
    role_name = user.role.name if user.role else services.SELF_SERVICE_ROLE
    return UserOut(
        id=user.id, email=user.email, full_name=user.full_name,
        role_name=role_name, is_active=user.is_active, mfa_enabled=user.mfa_enabled,
        organization_id=user.organization_id,
    )


@app.post("/auth/login", response_model=TokenPair)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    # Dos limites en paralelo: por IP (frena a un atacante probando muchas
    # cuentas, o muchas passwords contra una) y por email (frena fuerza
    # bruta distribuida en varias IPs contra UNA cuenta puntual).
    await _enforce_rate_limit(f"login:ip:{_client_ip(request)}", limit=20)
    await _enforce_rate_limit(f"login:email:{payload.email.lower()}", limit=10)
    user = await services.authenticate(db, payload.email, payload.password, payload.totp_code)
    if user is None:
        login_attempts_total.labels(outcome="failure").inc()
        await services.record_audit_event(db, payload.email, "auth.login.failure")
        await db.commit()
        raise HTTPException(status_code=401, detail="Credenciales invalidas o MFA requerido")
    org = await services.get_organization_by_id(db, user.organization_id) if user.organization_id else None
    if org is not None:
        await _reject_if_org_inactive(db, org, payload.email)
    role_name = user.role.name if user.role else services.SELF_SERVICE_ROLE
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, payload.email, "auth.login.success")
    await db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


@app.post("/auth/google", response_model=TokenPair)
async def google_login(payload: GoogleAuthRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Login o registro con Google: el frontend manda el credential (ID token)
    que devuelve Google Identity Services; lo validamos contra los servers de
    Google (firma + audiencia == nuestro client id) antes de confiar en el
    email. No hay password ni MFA en este camino porque Google ya verifico
    al usuario."""
    await _enforce_rate_limit(f"google_login:ip:{_client_ip(request)}", limit=20)
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=503, detail="Login con Google no esta configurado en este servidor (falta GOOGLE_CLIENT_ID)")
    try:
        claims = google_id_token.verify_oauth2_token(payload.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
    except ValueError:
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=401, detail="Token de Google invalido o expirado")
    if not claims.get("email_verified", False):
        raise HTTPException(status_code=401, detail="El email de esa cuenta de Google no esta verificado")
    email = claims["email"]
    full_name = claims.get("name", "")
    if not services.self_registration_allowed():
        known = await services.get_user_by_email(db, email)
        if known is None and await services.count_users(db) > 0:
            raise HTTPException(
                status_code=403,
                detail="Esa cuenta de Google no esta autorizada. Pidele a un administrador que te de acceso.",
            )
    user = await services.get_or_create_google_user(db, email, full_name)
    # Igual que en /auth/register: si esta es la PRIMERA cuenta de la instalacion,
    # queda como admin (y platform_admin). Sin esto, el primero en entrar con
    # Google quedaba como viewer y nadie podia administrar el sistema.
    await services.promote_first_user_to_admin_if_needed(db)
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Esta cuenta esta desactivada. Contacta a un administrador.")
    org = await services.get_organization_by_id(db, user.organization_id) if user.organization_id else None
    if org is not None:
        await _reject_if_org_inactive(db, org, email)
    role_name = user.role.name if user.role else services.SELF_SERVICE_ROLE
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, email, "auth.google.login")
    await db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


@app.post("/auth/refresh", response_model=TokenPair)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Cambia un refresh_token vigente por un access_token nuevo (y un
    refresh_token nuevo). El access_token dura poco a proposito
    (ACCESS_TOKEN_EXPIRE_MINUTES, 15 minutos por defecto) -- sin este
    endpoint, el usuario quedaba con 401 ("Token invalido o expirado") en
    toda la plataforma pasados esos 15 minutos, sin otra opcion que cerrar
    sesion y volver a entrar. El frontend llama esto automaticamente
    (ver frontend/src/services/api.ts) apenas ve un 401."""
    try:
        claims = decode_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token invalido o expirado")
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Tipo de token incorrecto")
    user = await services.get_user_by_id(db, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuario no encontrado o inactivo")
    org = await services.get_organization_by_id(db, user.organization_id) if user.organization_id else None
    if org is not None:
        await _reject_if_org_inactive(db, org, user.email)
    role_name = user.role.name if user.role else services.SELF_SERVICE_ROLE
    access, new_refresh = services.issue_tokens(user, role_name)
    return TokenPair(access_token=access, refresh_token=new_refresh)


@app.post("/auth/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(
    payload: MfaEnrollRequest = MfaEnrollRequest(),
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    # BUG DE SEGURIDAD (corregido aca): antes esto pisaba mfa_secret sin
    # ninguna condicion -- cualquiera con un access_token valido (15 min,
    # robado via XSS, un dispositivo prestado, un token que quedo en un
    # log) podia llamar este endpoint para generarle a la victima un
    # secret de MFA NUEVO que el atacante ya conoce, y confirmarlo el
    # mismo con /auth/mfa/confirm -- sin necesitar el codigo TOTP real ni
    # la contrasena. mfa_enabled seguia en True todo el tiempo, asi que la
    # victima no veia ninguna señal de que su segundo factor cambio.
    # Ahora, si el usuario YA tiene MFA activo, re-enrolar (generar un
    # secret nuevo) exige probar primero que quien lo pide todavia
    # controla el dispositivo YA enrolado (un codigo TOTP valido del
    # secret actual) -- exactamente lo mismo que ya se le exige para
    # cualquier otra accion sensible de la cuenta.
    user = await db.get(services.User, claims["sub"])
    if user.mfa_enabled:
        await _enforce_rate_limit(f"mfa_reenroll:user:{claims['sub']}", limit=10)
        if not services.verify_current_totp(user, payload.totp_code):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Para reemplazar el MFA actual, primero confirma un codigo TOTP valido del dispositivo ya enrolado.",
            )
    secret, otpauth_url = await services.enroll_mfa(db, user)
    await db.commit()
    return MfaEnrollResponse(
        secret=secret, otpauth_url=otpauth_url, qr_code_data_uri=services.mfa_qr_data_uri(otpauth_url)
    )


@app.get("/auth/mfa/status", response_model=MfaStatusResponse)
async def mfa_status(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    """Para que la pantalla "Seguridad" sepa si ofrecer 'Activar' o 'Reemplazar'."""
    user = await db.get(services.User, claims["sub"])
    return MfaStatusResponse(enabled=bool(user and user.mfa_enabled))


@app.post("/auth/mfa/confirm")
async def mfa_confirm(payload: MfaVerifyRequest, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    # Un codigo TOTP son 6 digitos (10^6 combinaciones) y valid_window=1
    # deja ~3 codigos validos en cualquier momento -- sin limite, alguien
    # con un access_token robado/filtrado podria intentar habilitar MFA
    # con un codigo adivinado en vez del real.
    await _enforce_rate_limit(f"mfa_confirm:user:{claims['sub']}", limit=10)
    user = await db.get(services.User, claims["sub"])
    ok = await services.confirm_mfa(db, user, payload.totp_code)
    await db.commit()
    if not ok:
        raise HTTPException(status_code=400, detail="Codigo TOTP invalido")
    return {"mfa_enabled": True}


@app.get("/auth/admin/ping")
async def admin_ping(claims: dict = Depends(require_role("admin"))):
    return {"pong": True, "role": claims["role"]}


# --- Organizaciones (tenants) ---

@app.post("/auth/organizations", status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    claims: dict = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Crea una organizacion nueva y su primer usuario admin en un solo
    paso (ver el comentario en schemas.OrganizationCreate del por que no
    hay auto-registro publico de organizaciones)."""
    existing_user = await services.get_user_by_email(db, payload.admin_email)
    if existing_user:
        raise HTTPException(status_code=400, detail="El email ya esta registrado")
    org = await services.create_organization(db, payload.name)
    admin_user = await services.create_user(
        db, payload.admin_email, payload.admin_password, payload.admin_full_name,
        org.id, role_name="admin",
    )
    await services.record_audit_event(db, claims.get("sub", ""), "organization.create", org.id)
    await db.commit()
    return {
        "organization": OrganizationOut.model_validate(org),
        "admin_user": UserOut(
            id=admin_user.id, email=admin_user.email, full_name=admin_user.full_name,
            role_name="admin", is_active=admin_user.is_active, mfa_enabled=admin_user.mfa_enabled,
            organization_id=admin_user.organization_id,
        ),
    }


# --- Usuarios de la organizacion (alta con rol elegido por un admin) ---


def _user_admin_out(u) -> UserAdminOut:
    return UserAdminOut(
        id=u.id, email=u.email, full_name=u.full_name,
        role_name=u.role.name if u.role else services.SELF_SERVICE_ROLE,
        is_active=u.is_active, mfa_enabled=u.mfa_enabled, auth_provider=u.auth_provider,
    )


@app.get("/auth/organizations/{org_id}/users", response_model=list[UserAdminOut])
async def list_org_users(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    return [_user_admin_out(u) for u in await services.list_users_in_org(db, org_id)]


@app.post("/auth/organizations/{org_id}/users", response_model=UserAdminOut, status_code=status.HTTP_201_CREATED)
async def create_org_user(
    org_id: str,
    payload: UserAdminCreate,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Unica via donde se ELIGE el rol de una cuenta nueva: la hace un admin de
    la organizacion (o un platform_admin). Con password -> cuenta de email y
    contrasena; sin password -> cuenta que entra con Google, pre-aprobada con
    este rol."""
    if payload.role not in services.ASSIGNABLE_ROLES:
        raise HTTPException(status_code=422, detail=f"Rol invalido. Opciones: {', '.join(services.ASSIGNABLE_ROLES)}")
    if await services.get_organization_by_id(db, org_id) is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if await services.get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="El email ya esta registrado")
    invite_error = await services.invite_email_error(
        db, org_id, payload.email, caller_is_platform_admin=bool(claims.get("platform_admin")),
    )
    if invite_error:
        raise HTTPException(status_code=422, detail=invite_error)
    user = await services.admin_create_user(db, org_id, payload.email, payload.full_name, payload.role, payload.password)
    await services.record_audit_event(
        db, claims.get("sub", ""), "user.create_by_admin", f"{user.email}:{payload.role}"
    )
    await db.commit()
    return _user_admin_out(user)


@app.patch("/auth/organizations/{org_id}/users/{user_id}", response_model=UserAdminOut)
async def update_org_user(
    org_id: str,
    user_id: str,
    payload: UserAdminUpdate,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Cambia el rol o activa/desactiva una cuenta. Guardas: nadie puede cambiar
    su propio rol/estado (evita quedarse sin acceso por error) y la
    organizacion nunca se queda sin al menos un admin activo."""
    user = await services.get_user_in_org(db, org_id, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en esta organizacion")
    if user.is_platform_admin and not claims.get("platform_admin"):
        # Un admin de la organizacion no administra cuentas de plataforma (las que estan por encima de el).
        raise HTTPException(status_code=403, detail="No podes administrar una cuenta de administrador de plataforma")
    if payload.role is None and payload.is_active is None:
        raise HTTPException(status_code=422, detail="Indica que cambiar: role y/o is_active")
    if payload.role is not None and payload.role not in services.ASSIGNABLE_ROLES:
        raise HTTPException(status_code=422, detail=f"Rol invalido. Opciones: {', '.join(services.ASSIGNABLE_ROLES)}")
    if user.id == claims.get("sub"):
        raise HTTPException(status_code=400, detail="No puedes cambiar tu propio rol ni desactivarte a ti mismo.")

    current_role = user.role.name if user.role else services.SELF_SERVICE_ROLE
    new_role = payload.role if payload.role is not None else current_role
    new_active = payload.is_active if payload.is_active is not None else user.is_active
    loses_admin = current_role == "admin" and user.is_active and (new_role != "admin" or not new_active)
    if loses_admin and await services.count_active_admins(db, org_id) <= 1:
        raise HTTPException(status_code=400, detail="La organizacion tiene que conservar al menos un administrador activo.")

    if payload.role is not None and payload.role != current_role:
        role = await services.get_or_create_role(db, payload.role)
        user.role_id = role.id
        user.role = role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    await services.record_audit_event(
        db, claims.get("sub", ""), "user.update_by_admin", f"{user.email}:role={new_role},active={new_active}"
    )
    await db.commit()
    return _user_admin_out(user)


@app.post("/auth/organizations/{org_id}/users/{user_id}/mfa", response_model=MfaEnrollResponse)
async def admin_mfa_enroll_user(
    org_id: str,
    user_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """El admin genera el QR de MFA de OTRA cuenta de email y contrasena (alta
    con MFA vinculado, o telefono perdido). Deja el MFA de esa cuenta
    DESACTIVADO hasta que se confirme con un codigo real
    (POST .../mfa/confirm): asi nadie queda bloqueado por un QR que nunca se
    escaneo. Una cuenta propia usa /auth/mfa/enroll (exige su codigo actual)."""
    user = await services.get_user_in_org(db, org_id, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en esta organizacion")
    if user.is_platform_admin and not claims.get("platform_admin"):
        # Un admin de la organizacion no administra cuentas de plataforma (las que estan por encima de el).
        raise HTTPException(status_code=403, detail="No podes administrar una cuenta de administrador de plataforma")
    if user.id == claims.get("sub"):
        raise HTTPException(status_code=400, detail="Tu propio MFA se cambia desde Seguridad de la cuenta.")
    if user.auth_provider != "local":
        raise HTTPException(status_code=400, detail="Esta cuenta entra con Google/SSO: su MFA lo maneja ese proveedor.")
    await _enforce_rate_limit(f"admin_mfa_enroll:{claims.get('sub')}", limit=20)
    secret, otpauth_url = await services.enroll_mfa(db, user)
    user.mfa_enabled = False
    await services.record_audit_event(db, claims.get("sub", ""), "user.mfa_enroll_by_admin", user.email)
    await db.commit()
    return MfaEnrollResponse(
        secret=secret, otpauth_url=otpauth_url, qr_code_data_uri=services.mfa_qr_data_uri(otpauth_url)
    )


@app.post("/auth/organizations/{org_id}/users/{user_id}/mfa/confirm", response_model=UserAdminOut)
async def admin_mfa_confirm_user(
    org_id: str,
    user_id: str,
    payload: MfaVerifyRequest,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Activa el MFA de la cuenta si el codigo de 6 digitos que muestra la app
    recien vinculada es correcto (prueba de que el QR quedo escaneado)."""
    user = await services.get_user_in_org(db, org_id, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en esta organizacion")
    if user.is_platform_admin and not claims.get("platform_admin"):
        raise HTTPException(status_code=403, detail="No podes administrar una cuenta de administrador de plataforma")
    await _enforce_rate_limit(f"admin_mfa_confirm:{claims.get('sub')}", limit=10)
    if not await services.confirm_mfa(db, user, payload.totp_code.strip()):
        raise HTTPException(status_code=400, detail="El codigo no coincide. Revisa la hora del telefono y proba con el codigo nuevo.")
    await services.record_audit_event(db, claims.get("sub", ""), "user.mfa_confirm_by_admin", user.email)
    await db.commit()
    return _user_admin_out(user)


@app.get("/auth/organizations", response_model=list[OrganizationOut])
async def list_organizations(claims: dict = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)):
    return await services.list_organizations(db)


async def require_billing_admin(
    org_id: str,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """La licencia/suscripcion de PayPal es UNA por instalacion (todas las
    organizaciones se refrescan con la misma LICENSE_KEY), asi que cancelar el
    cobro, generar el link de pago o ver el historial afecta a todos los
    tenants. Un platform_admin siempre puede; el admin de una organizacion solo
    en instalaciones de UNA sola organizacion (el caso normal de un cliente
    autohospedado). En instalaciones multi-organizacion lo decide el operador."""
    if claims.get("platform_admin"):
        return claims
    if claims.get("role") == "admin" and claims.get("org_id") == org_id:
        if len(await services.list_organizations(db)) <= 1:
            return claims
        raise HTTPException(
            status_code=403,
            detail="La suscripcion es de toda la instalacion; pedile al administrador de plataforma.",
        )
    raise HTTPException(status_code=403, detail="Permisos insuficientes para esta organizacion")


@app.get("/internal/organizations")
async def internal_list_organizations(
    claims: dict = Depends(require_service_token),
    db: AsyncSession = Depends(get_db),
):
    """Endpoint interno (servicio-a-servicio: exige un JWT de servicio
    "system:*", ver dependencies.require_service_token; antes era anonimo y
    listaba los ids de todos los tenants). Solo expone ids, nada sensible: pensado para que otro servicio pueda recorrer
    "todas las organizaciones" sin necesitar un JWT de platform_admin
    (ej. case-service, para sincronizar pending-cases de soar-service de
    cada tenant en un ciclo de fondo -- ver case-service/app/main.py::
    _soar_sync_loop)."""
    orgs = await services.list_organizations(db)
    return [{"id": org.id} for org in orgs]


@app.get("/auth/organizations/{org_id}/sso", response_model=SsoConfigOut | None)
async def get_sso_config(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    config = await services.get_sso_config(db, org_id)
    return config


@app.put("/auth/organizations/{org_id}/sso", response_model=SsoConfigOut)
async def set_sso_config(
    org_id: str,
    payload: SsoConfigIn,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    # El issuer lo escribe un admin de la organizacion y este servicio hace
    # requests hacia el (SSRF): se rechaza al guardar si apunta a una red
    # interna (se vuelve a validar en cada request, ver app/oidc.py).
    try:
        oidc.check_idp_url(payload.issuer, field_name="issuer")
    except oidc.OidcError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    config = await services.upsert_sso_config(
        db, org_id, payload.issuer, payload.client_id, payload.client_secret,
        payload.default_role, payload.enabled,
    )
    await services.record_audit_event(db, claims.get("sub", ""), "sso_config.update", org_id)
    await db.commit()
    return config


# --- Suscripcion / licencia (ver app/models.py::Organization y
# backend/shared/license_check.py para el diseño completo) ---

@app.get("/auth/organizations/{org_id}/subscription", response_model=OrganizationOut)
async def get_subscription(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Solo lectura -- el admin de la propia organizacion puede ver
    cuando vence su suscripcion (para no tener que preguntarle al
    operador), pero no puede extenderla el mismo (ver el endpoint de
    abajo, que exige platform_admin)."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    return org


@app.post("/auth/organizations/{org_id}/subscription/refresh", response_model=OrganizationOut)
async def refresh_subscription(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Vuelve a consultar el servidor central de licencias YA (en vez de esperar
    al chequeo periodico de LICENSE_CHECK_INTERVAL_HOURS). Lo usa la pantalla
    de Pagos y licencia al abrirse y el boton "Actualizar": asi, despues de
    pagar, la fecha nueva aparece enseguida. No otorga nada: solo copia lo que
    el servidor central ya firmo; si no se puede consultar, deja todo igual."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    await _enforce_rate_limit(f"sub_refresh:{claims.get('sub')}", limit=30)
    await services.refresh_license_from_central_server(db, org_id)
    await db.commit()
    await db.refresh(org)
    return org


@app.post("/auth/organizations/{org_id}/subscription/extend", response_model=OrganizationOut)
async def extend_subscription(
    org_id: str,
    payload: SubscriptionExtendRequest,
    claims: dict = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Renovacion manual -- SOLO el operador de la plataforma (nunca el
    admin de la propia organizacion: extender su propia suscripcion
    "gratis" es exactamente lo que este gate existe para evitar). Es lo
    que se usa hoy, a mano, al confirmar un pago; el dia que el webhook
    de PayPal este conectado al servidor central de licencias, ese
    webhook llama al equivalente de esto en licensing-server (ver
    licensing-server/app/main.py::extend_client), no a este endpoint
    directamente -- este endpoint sigue sirviendo para instalaciones sin
    servidor central (LICENSE_SERVER_URL vacio) o para ajustes manuales
    puntuales."""
    org = await services.extend_subscription(db, org_id, payload.days)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    await services.record_audit_event(
        db, claims.get("sub", ""), "organization.subscription.extend", f"{org_id}:+{payload.days}d"
    )
    await db.commit()
    return org


@app.post("/auth/organizations/{org_id}/subscription/cancel-payment", response_model=SubscriptionCancelOut)
async def cancel_subscription_payment(
    org_id: str,
    claims: dict = Depends(require_billing_admin),
    db: AsyncSession = Depends(get_db),
):
    """Autoservicio -- a diferencia de extend_subscription (arriba), esto
    NO otorga ningun beneficio gratis (no toca subscription_expires_at),
    solo corta el PROXIMO cobro automatico de PayPal -- por eso el
    admin de la propia organizacion puede llamarlo el mismo, sin
    necesitar a un platform_admin. El acceso sigue activo hasta que
    venza el periodo ya pagado (ver license_check.cancel_subscription en
    backend/shared/license_check.py)."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if not license_check.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Esta instalacion no tiene un servidor central de licencias configurado -- "
            "para cancelar la suscripcion, contacta al operador.",
        )
    try:
        await license_check.cancel_subscription()
    except license_check.LicenseCheckError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await services.record_audit_event(
        db, claims.get("sub", ""), "organization.subscription.cancel_payment", org_id
    )
    await db.commit()
    return SubscriptionCancelOut(cancelled=True, valid_until=org.subscription_expires_at)


@app.post("/auth/organizations/{org_id}/subscription/pay-link", response_model=SubscriptionPayLinkOut)
async def get_subscription_pay_link(
    org_id: str,
    payload: SubscriptionPayLinkRequest = SubscriptionPayLinkRequest(),
    claims: dict = Depends(require_billing_admin),
    db: AsyncSession = Depends(get_db),
):
    """Autoservicio -- genera un link de pago (PayPal o Mercado Pago, segun
    `provider`; PayPal si no se manda) para esta organizacion, tanto para pagar por primera vez como para volver a
    suscribirse despues de haber cancelado (ver cancel_subscription_payment
    arriba) mientras el periodo ya pagado todavia no vencio. payer_email
    es el email de QUIEN ESTA LOGUEADO pidiendolo (se resuelve del JWT,
    nunca se le pide al frontend que lo mande) -- PayPal lo usa
    solo para vincular el pago, no hace falta que sea el admin de la
    organizacion en particular."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if not license_check.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Esta instalacion no tiene un servidor central de licencias configurado -- "
            "para pagar o renovar, contacta al operador.",
        )
    user = await services.get_user_by_id(db, claims.get("sub", ""))
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    provider = payload.provider
    if provider not in license_check.enabled_providers():
        raise HTTPException(
            status_code=400,
            detail=f"{license_check.provider_label(provider)} no esta habilitado en esta instalacion.",
        )
    try:
        payment_url = await license_check.get_payment_link(payload.payer_email or user.email, provider)
    except license_check.LicenseCheckError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not payment_url:
        raise HTTPException(
            status_code=503,
            detail=f"{license_check.provider_label(provider)} no esta configurado del lado del servidor central de licencias.",
        )
    await services.record_audit_event(db, claims.get("sub", ""), "organization.subscription.pay_link", org_id)
    await db.commit()
    return SubscriptionPayLinkOut(payment_url=payment_url)


@app.get("/auth/payment-providers", response_model=PaymentProvidersOut)
async def get_payment_providers(claims: dict = Depends(get_current_claims)):
    """Pasarelas que ofrece esta instalacion (PAYMENT_PROVIDERS del .env), para que
    "Pagos y licencia" muestre solo esas. No expone ningun dato de la licencia."""
    return PaymentProvidersOut(providers=license_check.enabled_providers())


@app.get("/auth/organizations/{org_id}/subscription/history", response_model=SubscriptionHistoryOut)
async def get_subscription_history(
    org_id: str,
    claims: dict = Depends(require_billing_admin),
    db: AsyncSession = Depends(get_db),
):
    """Solo lectura -- historial de pagos/cancelaciones/renovaciones de
    esta licencia, para que el admin de la organizacion no tenga que
    pedirselo al operador. Lista vacia (nunca error) si no hay servidor
    central configurado -- el frontend ya sabe mostrar "sin historial"
    en ese caso."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if not license_check.is_configured():
        return SubscriptionHistoryOut(history=[])
    try:
        history = await license_check.get_subscription_history()
    except license_check.LicenseCheckError as exc:
        logger.warning("no se pudo traer el historial de licencia para %s: %s", org_id, exc)
        return SubscriptionHistoryOut(history=[])
    return SubscriptionHistoryOut(history=history)


# --- SSO empresarial (OIDC) ---
#
# state es un JWT propio de vida MUY corta (5 min, tipo "oidc_state") que
# viaja ida y vuelta por la URL a traves del proveedor de identidad -- hace
# de proteccion CSRF (nadie mas puede fabricar uno valido sin nuestra
# JWT_SECRET_KEY) y de forma de pasar el org_id/nonce sin necesitar sesiones
# de servidor (esta API es stateless, como el resto de la plataforma).

_OIDC_BIND_COOKIE = "sentinelops_oidc_bind"
_OIDC_CLIENT_STATE_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")


def _oidc_redirect_uri(request: Request, org_slug: str) -> str:
    return str(request.url_for("oidc_callback", org_slug=org_slug))


@app.get("/auth/oidc/{org_slug}/login")
async def oidc_login(
    org_slug: str, request: Request, cs: str = "", db: AsyncSession = Depends(get_db),
):
    # cs = valor aleatorio que la SPA guarda en sessionStorage antes de redirigir y que el
    # callback devuelve en el fragmento: la SPA solo instala una sesion SSO si coincide, asi
    # un link armado a mano (/sso/callback#access_token=...) no puede iniciarle sesion a la
    # victima en la cuenta del atacante.
    if cs and not _OIDC_CLIENT_STATE_RE.fullmatch(cs):
        raise HTTPException(status_code=422, detail="cs invalido")
    org = await services.get_organization_by_slug(db, org_slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    config = await services.get_sso_config(db, org.id)
    if config is None or not config.enabled:
        raise HTTPException(status_code=404, detail="Esta organizacion no tiene SSO configurado/habilitado")

    nonce = secrets.token_urlsafe(16)
    state = create_token(org.id, timedelta(minutes=5), {"type": "oidc_state", "nonce": nonce, "cs": cs})
    try:
        authorize_url = await oidc.build_authorize_url(config, _oidc_redirect_uri(request, org_slug), state, nonce)
    except oidc.OidcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    response = RedirectResponse(authorize_url)
    # Liga el flujo al navegador que lo inicio: el callback exige esta cookie
    # (HttpOnly, SameSite=Lax viaja en la navegacion de vuelta del IdP). Sin ella
    # un atacante podia hacer que la victima abriera SU url de callback
    # (code+state del atacante) y dejarla logueada en la cuenta del atacante.
    response.set_cookie(
        _OIDC_BIND_COOKIE, nonce, max_age=300, httponly=True, samesite="lax",
        secure=FRONTEND_URL.lower().startswith("https://"), path="/auth/oidc",
    )
    return response


@app.get("/auth/oidc/{org_slug}/callback", name="oidc_callback")
async def oidc_callback(org_slug: str, request: Request, code: str, state: str, db: AsyncSession = Depends(get_db)):
    org = await services.get_organization_by_slug(db, org_slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    config = await services.get_sso_config(db, org.id)
    if config is None or not config.enabled:
        raise HTTPException(status_code=404, detail="Esta organizacion no tiene SSO configurado/habilitado")

    try:
        state_claims = decode_token(state)
    except JWTError:
        raise HTTPException(status_code=401, detail="state invalido o expirado -- volve a intentar el login")
    if state_claims.get("type") != "oidc_state" or state_claims.get("sub") != org.id:
        raise HTTPException(status_code=401, detail="state no corresponde a esta organizacion")
    nonce = state_claims.get("nonce", "")
    bound = request.cookies.get(_OIDC_BIND_COOKIE, "")
    if not nonce or not bound or not secrets.compare_digest(bound.encode(), nonce.encode()):
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=401, detail="El login SSO no se inicio en este navegador -- volve a empezar")

    try:
        tokens = await oidc.exchange_code(config, code, _oidc_redirect_uri(request, org_slug))
        id_token = tokens.get("id_token")
        if not id_token:
            raise oidc.OidcError("el proveedor no devolvio id_token")
        id_claims = await oidc.validate_id_token(config, id_token, nonce)
    except oidc.OidcError as exc:
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    email = id_claims["email"]
    full_name = id_claims.get("name", "")
    user = await services.get_or_create_oidc_user(db, email, full_name, org, config.default_role)
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Esta cuenta esta desactivada. Contacta a un administrador.")
    if user.is_platform_admin:
        # El IdP lo configura el admin de la organizacion; una cuenta con
        # autoridad de plataforma (por encima del admin de la org) no puede
        # ser autenticada por un IdP que el admin de una org controla.
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=403, detail="Las cuentas de administrador de plataforma no pueden entrar por SSO de una organizacion")
    if user.organization_id != org.id:
        # Un email que ya existe en OTRA organizacion no puede "entrar" a
        # esta via SSO -- evita que alguien con SSO mal configurado en la
        # empresa B termine autenticado como un usuario de la empresa A.
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=403, detail="Este email ya pertenece a otra organizacion")
    await _reject_if_org_inactive(db, org, email)

    role_name = user.role.name if user.role else config.default_role
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, email, "auth.oidc.login", org.id)
    await db.commit()

    fragment_params = {"access_token": access, "refresh_token": refresh}
    if state_claims.get("cs"):
        fragment_params["cs"] = state_claims["cs"]
    fragment = urlencode(fragment_params)
    response = RedirectResponse(f"{FRONTEND_URL}/sso/callback#{fragment}")
    response.delete_cookie(_OIDC_BIND_COOKIE, path="/auth/oidc")
    return response
