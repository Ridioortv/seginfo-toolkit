"""Flujo del registro con MFA: crear la cuenta -> entrar -> QR (enroll sin codigo previo) ->
confirmar con el codigo de la app -> desde ahi el login pide el codigo."""
import asyncio
import os
import tempfile

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import main, services
from backend.shared import rate_limit
from backend.shared.database import Base, get_db

PASSWORD = "contrasena-larga-1"


@pytest.fixture()
def client(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(prefix="auth-mfa-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as db:
            await services.create_organization(db, "Default")  # organizacion donde cae el auto-registro
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
    monkeypatch.setattr(services, "is_org_active", lambda org: True)  # SQLite pierde la zona horaria
    monkeypatch.setattr(services, "get_default_organization", services.get_default_organization)
    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def _login(c, email, code=None):
    return c.post("/auth/login", json={"email": email, "password": PASSWORD, "totp_code": code})


def _register(c, email):
    r = c.post("/auth/register", json={"email": email, "password": PASSWORD, "full_name": "N"})
    assert r.status_code == 201
    return r.json()


def test_register_returns_qr_and_confirming_links_mfa(client):
    c = client
    reg = _register(c, "nuevo@acme.com")
    # el QR llega en la propia respuesta de "Crear cuenta" (sin iniciar sesion)
    assert reg["mfa_setup"]["qr_code_data_uri"].startswith("data:image/") and reg["mfa_setup"]["secret"]
    assert reg["mfa_setup_token"]
    # hasta confirmar, el login sigue sin pedir codigo
    assert _login(c, "nuevo@acme.com").status_code == 200

    code = pyotp.TOTP(reg["mfa_setup"]["secret"]).now()
    ok = c.post("/auth/register/mfa/confirm", json={"setup_token": reg["mfa_setup_token"], "totp_code": code})
    assert ok.status_code == 200

    # ya vinculado: sin codigo no entra, con el codigo de la app si
    assert _login(c, "nuevo@acme.com").status_code == 401
    assert _login(c, "nuevo@acme.com", "000000").status_code == 401
    assert _login(c, "nuevo@acme.com", pyotp.TOTP(reg["mfa_setup"]["secret"]).now()).status_code == 200


def test_wrong_code_does_not_link_mfa(client):
    c = client
    reg = _register(c, "otro@acme.com")
    bad = c.post("/auth/register/mfa/confirm", json={"setup_token": reg["mfa_setup_token"], "totp_code": "123456"})
    assert bad.status_code == 400
    assert _login(c, "otro@acme.com").status_code == 200  # nadie queda bloqueado por no terminar el paso


def test_confirm_works_even_if_org_subscription_expired(client, monkeypatch):
    """El caso del reporte: login da 402 (suscripcion vencida) pero el MFA igual se vincula."""
    c = client
    reg = _register(c, "vencida@acme.com")
    monkeypatch.setattr(services, "is_org_active", lambda org: False)
    assert _login(c, "vencida@acme.com").status_code == 402
    code = pyotp.TOTP(reg["mfa_setup"]["secret"]).now()
    assert c.post("/auth/register/mfa/confirm", json={"setup_token": reg["mfa_setup_token"], "totp_code": code}).status_code == 200


def test_setup_token_is_single_use_and_garbage_rejected(client):
    c = client
    reg = _register(c, "uso@acme.com")
    code = pyotp.TOTP(reg["mfa_setup"]["secret"]).now()
    body = {"setup_token": reg["mfa_setup_token"], "totp_code": code}
    assert c.post("/auth/register/mfa/confirm", json=body).status_code == 200
    assert c.post("/auth/register/mfa/confirm", json=body).status_code == 400  # ya vinculado
    assert c.post("/auth/register/mfa/confirm", json={"setup_token": "basura" * 10, "totp_code": code}).status_code == 400
