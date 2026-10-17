"""Alta de cuentas con rol elegido por un ADMIN, y minimo privilegio para el resto."""
import asyncio
import os
import tempfile

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import main, services
from app.dependencies import require_role
from backend.shared import security
from backend.shared.database import Base, get_db


@pytest.fixture()
def env(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(prefix="auth-test-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as db:
            org = await services.create_organization(db, "Acme")
            other = await services.create_organization(db, "Otra")
            admin = await services.create_user(db, "admin@acme.com", "x" * 12, "Admin", org.id, role_name="admin")
            await db.commit()
            return org.id, other.id, admin.id

    org_id, other_id, admin_id = asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    monkeypatch.delenv("ALLOW_SELF_REGISTRATION", raising=False)
    client = TestClient(main.app)  # sin 'with': no corre el lifespan (es solo Postgres)

    def token(user_id, role, org, platform_admin=False):
        return {"Authorization": "Bearer " + security.create_access_token(user_id, role, org, platform_admin)}

    yield client, Session, org_id, other_id, admin_id, token
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def _users(client, org, hdr):
    r = client.get(f"/auth/organizations/{org}/users", headers=hdr)
    assert r.status_code == 200
    return {u["email"]: u for u in r.json()}


def test_admin_creates_local_and_google_accounts_with_chosen_role(env):
    client, _, org, _, admin_id, token = env
    h = token(admin_id, "admin", org)
    r = client.post(f"/auth/organizations/{org}/users", headers=h,
                    json={"email": "ana@acme.com", "full_name": "Ana", "role": "analyst", "password": "contrasena-larga-1"})
    assert r.status_code == 201 and r.json()["role_name"] == "analyst" and r.json()["auth_provider"] == "local"
    r = client.post(f"/auth/organizations/{org}/users", headers=h,
                    json={"email": "gus@acme.com", "role": "viewer"})  # sin password -> Google
    assert r.status_code == 201 and r.json()["role_name"] == "viewer" and r.json()["auth_provider"] == "google"
    assert set(_users(client, org, h)) == {"admin@acme.com", "ana@acme.com", "gus@acme.com"}


def test_invalid_role_is_rejected(env):
    client, _, org, _, admin_id, token = env
    h = token(admin_id, "admin", org)
    for bad in ("superuser", "platform_admin", ""):
        r = client.post(f"/auth/organizations/{org}/users", headers=h,
                        json={"email": "x@acme.com", "role": bad, "password": "contrasena-larga-1"})
        assert r.status_code == 422


@pytest.mark.parametrize("role", ["analyst", "viewer", "soc_manager"])
def test_only_admins_can_create_users(env, role):
    client, _, org, _, admin_id, token = env
    r = client.post(f"/auth/organizations/{org}/users", headers=token("someone", role, org),
                    json={"email": "x@acme.com", "role": "admin", "password": "contrasena-larga-1"})
    assert r.status_code == 403


def test_admin_of_another_org_cannot_manage_this_org(env):
    client, _, org, other, _, token = env
    h = token("admin-b", "admin", other)
    assert client.get(f"/auth/organizations/{org}/users", headers=h).status_code == 403
    assert client.post(f"/auth/organizations/{org}/users", headers=h,
                       json={"email": "x@acme.com", "role": "admin", "password": "contrasena-larga-1"}).status_code == 403


def test_cannot_change_own_role_or_remove_last_admin(env):
    client, _, org, _, admin_id, token = env
    h = token(admin_id, "admin", org)
    assert client.patch(f"/auth/organizations/{org}/users/{admin_id}", headers=h, json={"role": "viewer"}).status_code == 400
    # un platform_admin tampoco puede dejar la organizacion sin admins
    hp = token("platform", "admin", "otro-org", platform_admin=True)
    r = client.patch(f"/auth/organizations/{org}/users/{admin_id}", headers=hp, json={"role": "viewer"})
    assert r.status_code == 400 and "al menos un administrador" in r.json()["detail"]


def test_change_role_and_deactivate_blocks_login(env):
    client, Session, org, _, admin_id, token = env
    h = token(admin_id, "admin", org)
    uid = client.post(f"/auth/organizations/{org}/users", headers=h,
                      json={"email": "ana@acme.com", "role": "viewer", "password": "contrasena-larga-1"}).json()["id"]
    r = client.patch(f"/auth/organizations/{org}/users/{uid}", headers=h, json={"role": "analyst"})
    assert r.status_code == 200 and r.json()["role_name"] == "analyst"

    async def can_login():
        async with Session() as db:
            return await services.authenticate(db, "ana@acme.com", "contrasena-larga-1", None)

    assert asyncio.run(can_login()) is not None
    assert client.patch(f"/auth/organizations/{org}/users/{uid}", headers=h, json={"is_active": False}).status_code == 200
    assert asyncio.run(can_login()) is None


def test_self_registration_gets_least_privilege_role(env):
    client, _, org, _, admin_id, token = env
    r = client.post("/auth/register", json={"email": "nuevo@x.com", "password": "contrasena-larga-1", "full_name": "N"})
    assert r.status_code == 201
    assert r.json()["role_name"] == "viewer"  # nunca elige su rol; ya existe un admin


def test_self_registration_can_be_closed_after_first_user(env, monkeypatch):
    client, *_ = env
    monkeypatch.setenv("ALLOW_SELF_REGISTRATION", "false")
    r = client.post("/auth/register", json={"email": "nuevo@x.com", "password": "contrasena-larga-1"})
    assert r.status_code == 403


def test_viewer_cannot_pass_write_guards():
    guard = require_role("admin", "soc_manager", "analyst")
    with pytest.raises(HTTPException) as exc:
        guard({"role": "viewer"})
    assert exc.value.status_code == 403
    assert guard({"role": "analyst"})["role"] == "analyst"


@pytest.fixture()
def empty_env(monkeypatch):
    """Instalacion recien hecha: no existe ningun usuario."""
    path = os.path.join(tempfile.mkdtemp(prefix="auth-empty-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as db:
            await services.get_default_organization(db)
            await db.commit()

    asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    monkeypatch.delenv("ALLOW_SELF_REGISTRATION", raising=False)
    yield TestClient(main.app), Session
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def test_first_registered_user_is_admin_and_second_is_viewer(empty_env):
    client, _ = empty_env
    r1 = client.post("/auth/register", json={"email": "primero@x.com", "password": "contrasena-larga-1"})
    assert r1.status_code == 201 and r1.json()["role_name"] == "admin"
    r2 = client.post("/auth/register", json={"email": "segundo@x.com", "password": "contrasena-larga-1"})
    assert r2.status_code == 201 and r2.json()["role_name"] == "viewer"


def test_first_registration_works_even_if_open_signup_is_closed(empty_env, monkeypatch):
    client, _ = empty_env
    monkeypatch.setenv("ALLOW_SELF_REGISTRATION", "false")
    assert client.post("/auth/register", json={"email": "primero@x.com", "password": "contrasena-larga-1"}).status_code == 201
    assert client.post("/auth/register", json={"email": "segundo@x.com", "password": "contrasena-larga-1"}).status_code == 403


def test_first_google_user_is_admin_in_memory_and_in_token(empty_env):
    _, Session = empty_env

    async def run():
        async with Session() as db:
            u1 = await services.get_or_create_google_user(db, "primero@gmail.com", "Primero")
            await services.promote_first_user_to_admin_if_needed(db)
            tokens = services.issue_tokens(u1, u1.role.name)
            await db.commit()
            u2 = await services.get_or_create_google_user(db, "segundo@gmail.com", "Segundo")
            await services.promote_first_user_to_admin_if_needed(db)
            return u1.role.name, u1.is_platform_admin, security.decode_token(tokens[0])["role"], u2.role.name

    r1, plat, tok_role, r2 = asyncio.run(run())
    assert (r1, plat, tok_role, r2) == ("admin", True, "admin", "viewer")


def test_admin_links_mfa_qr_for_another_account_and_confirms(env):
    import pyotp
    client, Session, org, other, admin_id, token = env
    h = token(admin_id, "admin", org)
    uid = client.post(f"/auth/organizations/{org}/users", headers=h,
                      json={"email": "ana@acme.com", "role": "analyst", "password": "p" * 12}).json()["id"]
    r = client.post(f"/auth/organizations/{org}/users/{uid}/mfa", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["qr_code_data_uri"].startswith("data:image/svg+xml;base64,")
    # hasta confirmar, el MFA sigue desactivado (no bloquea el login)
    assert _users(client, org, h)["ana@acme.com"]["mfa_enabled"] is False
    bad = client.post(f"/auth/organizations/{org}/users/{uid}/mfa/confirm", headers=h, json={"totp_code": "000000"})
    assert bad.status_code == 400
    ok = client.post(f"/auth/organizations/{org}/users/{uid}/mfa/confirm", headers=h,
                     json={"totp_code": pyotp.TOTP(body["secret"]).now()})
    assert ok.status_code == 200 and ok.json()["mfa_enabled"] is True
    # y ahora el login exige el codigo
    async def check():
        async with Session() as db:
            assert await services.authenticate(db, "ana@acme.com", "p" * 12, None) is None
            assert await services.authenticate(db, "ana@acme.com", "p" * 12, pyotp.TOTP(body["secret"]).now()) is not None
    asyncio.run(check())


def test_admin_mfa_endpoints_are_guarded(env):
    client, _, org, other, admin_id, token = env
    h = token(admin_id, "admin", org)
    # no sobre uno mismo
    assert client.post(f"/auth/organizations/{org}/users/{admin_id}/mfa", headers=h).status_code == 400
    google_id = client.post(f"/auth/organizations/{org}/users", headers=h,
                            json={"email": "g@acme.com", "role": "viewer"}).json()["id"]
    assert client.post(f"/auth/organizations/{org}/users/{google_id}/mfa", headers=h).status_code == 400
    # un analista no puede
    analyst = token("someone", "analyst", org)
    assert client.post(f"/auth/organizations/{org}/users/{google_id}/mfa", headers=analyst).status_code == 403
    # admin de otra organizacion no puede
    other_admin = token("x", "admin", other)
    assert client.post(f"/auth/organizations/{org}/users/{google_id}/mfa", headers=other_admin).status_code == 403


def test_subscription_refresh_endpoint_is_admin_only_and_safe(env, monkeypatch):
    """/subscription/refresh: solo admin de la organizacion; sin servidor central
    configurado no rompe ni cambia nada."""
    client, _, org, other, admin_id, token = env
    h = token(admin_id, "admin", org)
    before = client.get(f"/auth/organizations/{org}/subscription", headers=h).json()["subscription_expires_at"]
    r = client.post(f"/auth/organizations/{org}/subscription/refresh", headers=h)
    assert r.status_code == 200 and r.json()["subscription_expires_at"] == before
    assert client.post(f"/auth/organizations/{org}/subscription/refresh", headers=token("x", "analyst", org)).status_code == 403
    assert client.post(f"/auth/organizations/{org}/subscription/refresh", headers=token("y", "admin", other)).status_code == 403


def test_org_admin_cannot_preapprove_email_of_a_foreign_domain(env):
    """Hallazgo cross-org-email-preapproval: el admin de un tenant no puede dar de
    alta el email de una persona ajena (quedaria capturada al entrar con Google)."""
    client, _, org, _, admin_id, token = env
    h = token(admin_id, "admin", org)
    for email in ("victima@corp-ajena.com", "persona@gmail.com"):
        r = client.post(f"/auth/organizations/{org}/users", headers=h,
                        json={"email": email, "full_name": "X", "role": "viewer"})
        assert r.status_code == 422, email
        r = client.post(f"/auth/organizations/{org}/users", headers=h,
                        json={"email": email, "full_name": "X", "role": "viewer", "password": "y" * 12})
        assert r.status_code == 422, email
    # mismo dominio que los usuarios de la organizacion: permitido
    r = client.post(f"/auth/organizations/{org}/users", headers=h,
                    json={"email": "nuevo@acme.com", "full_name": "N", "role": "viewer"})
    assert r.status_code == 201


def test_platform_admin_can_preapprove_any_email(env):
    client, _, org, _, admin_id, token = env
    h = token(admin_id, "admin", org, platform_admin=True)
    r = client.post(f"/auth/organizations/{org}/users", headers=h,
                    json={"email": "cliente@gmail.com", "full_name": "C", "role": "viewer"})
    assert r.status_code == 201


def test_freemail_invites_can_be_enabled_for_single_company_installs(env, monkeypatch):
    client, _, org, _, admin_id, token = env
    monkeypatch.setenv("ALLOW_FREEMAIL_INVITES", "true")
    h = token(admin_id, "admin", org)
    r = client.post(f"/auth/organizations/{org}/users", headers=h,
                    json={"email": "empleado@gmail.com", "full_name": "E", "role": "viewer"})
    assert r.status_code == 201
