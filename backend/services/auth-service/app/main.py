"""auth-service entrypoint: identity, JWT issuance, MFA (TOTP), RBAC."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from app.schemas import UserCreate, UserOut, LoginRequest, TokenPair, MfaEnrollResponse, MfaVerifyRequest
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("auth-service")
login_attempts_total = Counter("auth_login_attempts_total", "Login attempts", ["outcome"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
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
    existing = await services.get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="El email ya esta registrado")
    user = await services.create_user(db, payload.email, payload.password, payload.full_name, payload.role_name)
    await services.record_audit_event(db, payload.email, "user.register")
    await db.commit()
    return UserOut(
        id=user.id, email=user.email, full_name=user.full_name,
        role_name=payload.role_name, is_active=user.is_active, mfa_enabled=user.mfa_enabled,
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
