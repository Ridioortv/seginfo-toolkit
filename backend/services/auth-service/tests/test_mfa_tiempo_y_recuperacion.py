"""QA: mas tiempo para escanear el QR del MFA al crear la cuenta + recuperacion de contrasena."""
import asyncio
import os
import tempfile
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import cli_password, main, password_reset, services
from backend.shared import rate_limit
from backend.shared.database import Base, get_db
from backend.shared.security import create_token, decode_token

PASSWORD = "contrasena-larga-1"


@pytest.fixture()
def env(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(prefix="auth-qa-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as db:
            await services.create_organization(db, "Default")
            await db.commit()

    asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    class Down:
        async def incr(self, *a, **k):
            raise ConnectionError()
        get = delete = expire = incr

    monkeypatch.setattr(rate_limit, "_get_redis", lambda: Down())
    getattr(rate_limit, "_fail_memory", {}).clear()
    rate_limit._fallback_counts.clear()
    monkeypatch.setattr(services, "is_org_active", lambda org: True)
    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app), Session
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def _register(c, email):
    r = c.post("/auth/register", json={"email": email, "password": PASSWORD, "full_name": "N"})
    assert r.status_code == 201
    return r.json()


def test_tiempo_para_escanear_por_defecto_es_de_2_horas(env, monkeypatch):
    monkeypatch.delenv("MFA_SETUP_TOKEN_MINUTES", raising=False)
    c, _ = env
    reg = _register(c, "tiempo@acme.com")
    assert reg["mfa_setup_expires_minutes"] == 120
    claims = decode_token(reg["mfa_setup_token"])
    import time
    assert 119 * 60 <= claims["exp"] - time.time() <= 121 * 60


def test_tiempo_se_puede_ajustar_y_tiene_limites(monkeypatch):
    monkeypatch.setenv("MFA_SETUP_TOKEN_MINUTES", "300")
    assert main._setup_minutes() == 300
    monkeypatch.setenv("MFA_SETUP_TOKEN_MINUTES", "1")
    assert main._setup_minutes() == 5
    monkeypatch.setenv("MFA_SETUP_TOKEN_MINUTES", "999999")
    assert main._setup_minutes() == 1440
    monkeypatch.setenv("MFA_SETUP_TOKEN_MINUTES", "no-es-numero")
    assert main._setup_minutes() == 120


def test_el_token_de_hace_una_hora_todavia_sirve(env):
    """Antes vencia a los 30 min: con 2 h la persona tiene margen de sobra para instalar la app."""
    c, Session = env
    reg = _register(c, "tarde@acme.com")
    old = create_token(
        decode_token(reg["mfa_setup_token"])["sub"], timedelta(minutes=60),
        {"type": "mfa_setup", "msf": password_reset.fingerprint(reg["mfa_setup"]["secret"])},
    )
    code = pyotp.TOTP(reg["mfa_setup"]["secret"]).now()
    assert c.post("/auth/register/mfa/confirm", json={"setup_token": old, "totp_code": code}).status_code == 200


def test_al_vincular_se_tolera_un_codigo_de_hasta_un_minuto_antes(env):
    import time
    c, _ = env
    reg = _register(c, "reloj@acme.com")
    totp = pyotp.TOTP(reg["mfa_setup"]["secret"])
    viejo = totp.at(time.time() - 60)  # 2 pasos de 30 s atras
    r = c.post("/auth/register/mfa/confirm", json={"setup_token": reg["mfa_setup_token"], "totp_code": viejo})
    assert r.status_code == 200
    # pero el LOGIN sigue con la tolerancia de siempre (1 paso): un codigo de hace 2 pasos no entra
    viejo2 = totp.at(time.time() - 90)
    r = c.post("/auth/login", json={"email": "reloj@acme.com", "password": PASSWORD, "totp_code": viejo2})
    assert r.status_code == 401


def test_recovery_info_dice_si_hay_mail(env, monkeypatch):
    c, _ = env
    monkeypatch.delenv("SMTP_HOST", raising=False)
    r = c.get("/auth/password/recovery-info")
    assert r.status_code == 200 and r.json() == {"email_enabled": False, "expires_minutes": 30}
    monkeypatch.setenv("SMTP_HOST", "smtp.empresa.com")
    assert c.get("/auth/password/recovery-info").json()["email_enabled"] is True


def test_consola_genera_link_que_sirve_para_cambiar_la_contrasena(env, monkeypatch):
    c, Session = env
    _register(c, "olvido@acme.com")
    monkeypatch.setattr(cli_password, "SessionLocal", Session)
    codigo, url = asyncio.run(cli_password.generar_link("olvido@acme.com"))
    assert codigo == 0 and "/restablecer?token=" in url
    from urllib.parse import parse_qs, urlparse
    token = parse_qs(urlparse(url).query)["token"][0]
    nueva = "otra-contrasena-larga-2"
    assert c.post("/auth/password/reset", json={"token": token, "new_password": nueva}).status_code == 200
    ok = c.post("/auth/login", json={"email": "olvido@acme.com", "password": nueva})
    assert ok.status_code == 200
    # un solo uso
    assert c.post("/auth/password/reset", json={"token": token, "new_password": "y-otra-contrasena-3"}).status_code == 400


def test_consola_no_inventa_cuentas_ni_links_para_google(env, monkeypatch):
    c, Session = env
    monkeypatch.setattr(cli_password, "SessionLocal", Session)
    assert asyncio.run(cli_password.generar_link("nadie@acme.com"))[0] == 1


def test_public_config_expone_el_client_id_de_google_sin_recompilar(env, monkeypatch):
    c, _ = env
    monkeypatch.setattr(main, "GOOGLE_CLIENT_ID", "")
    assert c.get("/auth/public-config").json() == {"google_client_id": None}
    monkeypatch.setattr(main, "GOOGLE_CLIENT_ID", "123-abc.apps.googleusercontent.com")
    assert c.get("/auth/public-config").json() == {"google_client_id": "123-abc.apps.googleusercontent.com"}
