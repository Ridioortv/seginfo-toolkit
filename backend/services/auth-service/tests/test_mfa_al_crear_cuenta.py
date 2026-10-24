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
    rate_limit._fail_memory.clear()
    rate_limit._fallback_counts.clear()
    monkeypatch.setattr(services, "is_org_active", lambda org: True)  # SQLite pierde la zona horaria
    monkeypatch.setattr(services, "get_default_organization", services.get_default_organization)
    main.app.dependency_overrides[get_db] = override
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def _login(c, email, code=None):
    return c.post("/auth/login", json={"email": email, "password": PASSWORD, "totp_code": code})


def test_new_account_enters_without_mfa_and_can_link_it_right_away(client):
    c = client
    assert c.post("/auth/register", json={"email": "nuevo@acme.com", "password": PASSWORD, "full_name": "N"}).status_code == 201
    first = _login(c, "nuevo@acme.com")
    assert first.status_code == 200  # sin MFA todavia: entra
    headers = {"Authorization": "Bearer " + first.json()["access_token"]}

    # el QR del alta: primer enrolamiento, sin pedir codigo previo
    enroll = c.post("/auth/mfa/enroll", headers=headers, json={})
    assert enroll.status_code == 200
    body = enroll.json()
    assert body["qr_code_data_uri"].startswith("data:image/") and body["secret"]
    # hasta confirmar, el login sigue sin pedir codigo (no se bloquea a nadie por abandonar el paso)
    assert _login(c, "nuevo@acme.com").status_code == 200

    code = pyotp.TOTP(body["secret"]).now()
    assert c.post("/auth/mfa/confirm", headers=headers, json={"totp_code": code}).status_code == 200
    assert c.get("/auth/mfa/status", headers=headers).json() == {"enabled": True}

    # ya vinculado: sin codigo no entra, con el codigo de la app si
    assert _login(c, "nuevo@acme.com").status_code == 401
    assert _login(c, "nuevo@acme.com", "000000").status_code == 401
    assert _login(c, "nuevo@acme.com", pyotp.TOTP(body["secret"]).now()).status_code == 200


def test_wrong_code_does_not_link_mfa(client):
    c = client
    c.post("/auth/register", json={"email": "otro@acme.com", "password": PASSWORD, "full_name": "O"})
    headers = {"Authorization": "Bearer " + _login(c, "otro@acme.com").json()["access_token"]}
    c.post("/auth/mfa/enroll", headers=headers, json={})
    assert c.post("/auth/mfa/confirm", headers=headers, json={"totp_code": "123456"}).status_code in (400, 401, 422)
    assert c.get("/auth/mfa/status", headers=headers).json() == {"enabled": False}
    assert _login(c, "otro@acme.com").status_code == 200
