"""auth-service entrypoint: identidad, organizaciones (tenants), JWT
issuance, MFA (TOTP), SSO empresarial (OIDC), RBAC."""
import os
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import urlencode
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from jose import JWTError
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.security import decode_token, create_token
from app.schemas import (
    UserCreate,
    UserOut,
    LoginRequest,
    TokenPair,
    MfaEnrollResponse,
    MfaVerifyRequest,
    GoogleAuthRequest,
    RefreshRequest,
    OrganizationCreate,
    OrganizationOut,
    SsoConfigIn,
    SsoConfigOut,
)
from app.dependencies import get_current_claims, require_role, require_platform_admin, require_org_admin_or_platform_admin
from app import services, oidc

logger = configure_logging("auth-service")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
# A donde se redirige al navegador despues de un login SSO exitoso (con los
# tokens en el fragmento de la URL, ver /auth/oidc/{slug}/callback). El
# frontend tiene que tener una ruta que los lea de ahi -- ver
# frontend/src/pages/SsoCallback.tsx.
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
login_attempts_total = Counter("auth_login_attempts_total", "Login attempts", ["outcome"])


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
    async with SessionLocal() as session:
        await services.promote_first_user_to_admin_if_needed(session)
        await services.backfill_users_without_organization(session)
        await session.commit()
    logger.info("auth-service iniciado")
    yield


app = FastAPI(title="SentinelOps Auth Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
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
    default_org = await services.get_default_organization(db)
    user = await services.create_user(db, payload.email, payload.password, payload.full_name, default_org.id)
    await services.promote_first_user_to_admin_if_needed(db)
    await services.record_audit_event(db, payload.email, "user.register")
    await db.commit()
    # Recargar con el rol ya resuelto (create_user no lo trae eager-loaded,
    # y promote_first_user_to_admin_if_needed puede haberlo cambiado).
    user = await services.get_user_by_email(db, payload.email)
    role_name = user.role.name if user.role else "analyst"
    return UserOut(
        id=user.id, email=user.email, full_name=user.full_name,
        role_name=role_name, is_active=user.is_active, mfa_enabled=user.mfa_enabled,
        organization_id=user.organization_id,
    )


@app.post("/auth/login", response_model=TokenPair)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await services.authenticate(db, payload.email, payload.password, payload.totp_code)
    if user is None:
        login_attempts_total.labels(outcome="failure").inc()
        await services.record_audit_event(db, payload.email, "auth.login.failure")
        await db.commit()
        raise HTTPException(status_code=401, detail="Credenciales invalidas o MFA requerido")
    role_name = user.role.name if user.role else "analyst"
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, payload.email, "auth.login.success")
    await db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


@app.post("/auth/google", response_model=TokenPair)
async def google_login(payload: GoogleAuthRequest, db: AsyncSession = Depends(get_db)):
    """Login o registro con Google: el frontend manda el credential (ID token)
    que devuelve Google Identity Services; lo validamos contra los servers de
    Google (firma + audiencia == nuestro client id) antes de confiar en el
    email. No hay password ni MFA en este camino porque Google ya verifico
    al usuario."""
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
    user = await services.get_or_create_google_user(db, email, full_name)
    role_name = user.role.name if user.role else "analyst"
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
    role_name = user.role.name if user.role else "analyst"
    access, new_refresh = services.issue_tokens(user, role_name)
    return TokenPair(access_token=access, refresh_token=new_refresh)


@app.post("/auth/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    user = await db.get(services.User, claims["sub"])
    secret, otpauth_url = await services.enroll_mfa(db, user)
    await db.commit()
    return MfaEnrollResponse(secret=secret, otpauth_url=otpauth_url)


@app.post("/auth/mfa/confirm")
async def mfa_confirm(payload: MfaVerifyRequest, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
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


@app.get("/auth/organizations", response_model=list[OrganizationOut])
async def list_organizations(claims: dict = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)):
    return await services.list_organizations(db)


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
    config = await services.upsert_sso_config(
        db, org_id, payload.issuer, payload.client_id, payload.client_secret,
        payload.default_role, payload.enabled,
    )
    await services.record_audit_event(db, claims.get("sub", ""), "sso_config.update", org_id)
    await db.commit()
    return config


# --- SSO empresarial (OIDC) ---
#
# state es un JWT propio de vida MUY corta (5 min, tipo "oidc_state") que
# viaja ida y vuelta por la URL a traves del proveedor de identidad -- hace
# de proteccion CSRF (nadie mas puede fabricar uno valido sin nuestra
# JWT_SECRET_KEY) y de forma de pasar el org_id/nonce sin necesitar sesiones
# de servidor (esta API es stateless, como el resto de la plataforma).

def _oidc_redirect_uri(request: Request, org_slug: str) -> str:
    return str(request.url_for("oidc_callback", org_slug=org_slug))


@app.get("/auth/oidc/{org_slug}/login")
async def oidc_login(org_slug: str, request: Request, db: AsyncSession = Depends(get_db)):
    org = await services.get_organization_by_slug(db, org_slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    config = await services.get_sso_config(db, org.id)
    if config is None or not config.enabled:
        raise HTTPException(status_code=404, detail="Esta organizacion no tiene SSO configurado/habilitado")

    nonce = secrets.token_urlsafe(16)
    state = create_token(org.id, timedelta(minutes=5), {"type": "oidc_state", "nonce": nonce})
    try:
        authorize_url = await oidc.build_authorize_url(config, _oidc_redirect_uri(request, org_slug), state, nonce)
    except oidc.OidcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(authorize_url)


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
    if user.organization_id != org.id:
        # Un email que ya existe en OTRA organizacion no puede "entrar" a
        # esta via SSO -- evita que alguien con SSO mal configurado en la
        # empresa B termine autenticado como un usuario de la empresa A.
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=403, detail="Este email ya pertenece a otra organizacion")

    role_name = user.role.name if user.role else config.default_role
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, email, "auth.oidc.login", org.id)
    await db.commit()

    fragment = urlencode({"access_token": access, "refresh_token": refresh})
    return RedirectResponse(f"{FRONTEND_URL}/sso/callback#{fragment}")
