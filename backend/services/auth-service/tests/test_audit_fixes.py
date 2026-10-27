"""Regresiones de la auditoria de seguridad (SSRF en OIDC, pre-claim de email,
endpoints internos, suscripcion de toda la instalacion)."""
import asyncio
import pytest
from fastapi.testclient import TestClient

import app.main as m
from app import oidc, services


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest",
    "http://10.0.0.5/",
    "http://localhost/",
    "file:///etc/passwd",
])
def test_oidc_rejects_internal_or_non_http_urls(url, monkeypatch):
    monkeypatch.delenv("OIDC_ALLOW_PRIVATE_NETWORK", raising=False)
    with pytest.raises(oidc.OidcError):
        oidc.check_idp_url(url)


def test_oidc_private_idp_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("OIDC_ALLOW_PRIVATE_NETWORK", "true")
    oidc.check_idp_url("http://10.0.0.5/realms/x")  # no levanta


def test_oidc_fetch_is_blocked_before_any_request(monkeypatch):
    monkeypatch.delenv("OIDC_ALLOW_PRIVATE_NETWORK", raising=False)
    with pytest.raises(oidc.OidcError):
        asyncio.run(oidc._get_json_cached("http://127.0.0.1:9/.well-known/openid-configuration", {}))


class _User:
    def __init__(self, **kw):
        self.is_platform_admin = False
        self.auth_provider = "local"
        self.hashed_password = "hash"
        self.mfa_enabled = True
        self.mfa_secret = "S"
        self.organization_id = "org-1"
        self.__dict__.update(kw)


class _Db:
    async def flush(self):
        pass


def test_federated_login_wipes_preregistered_password_and_mfa():
    u = _User()
    asyncio.run(services._adopt_local_account_for_federated_login(_Db(), u, "google"))
    assert u.hashed_password is None and u.mfa_secret is None and u.mfa_enabled is False
    assert u.auth_provider == "google"


def test_platform_admin_account_is_not_touched():
    u = _User(is_platform_admin=True)
    asyncio.run(services._adopt_local_account_for_federated_login(_Db(), u, "oidc"))
    assert u.hashed_password == "hash" and u.mfa_enabled is True


def test_oidc_of_other_org_cannot_wipe_a_victim_password(monkeypatch):
    victim = _User(organization_id="org-A")

    async def by_email(db, email):
        return victim

    monkeypatch.setattr(services, "get_user_by_email", by_email)

    class Org:
        id = "org-B"

    asyncio.run(services.get_or_create_oidc_user(_Db(), "v@x.com", "V", Org(), "viewer"))
    assert victim.hashed_password == "hash"


def test_internal_organizations_requires_service_token():
    async def fake_db():
        yield None

    m.app.dependency_overrides[m.get_db] = fake_db
    try:
        c = TestClient(m.app)
        assert c.get("/internal/organizations").status_code == 401
        from backend.shared.security import create_access_token
        user_tok = create_access_token("some-user-uuid", "admin", "org-1")
        r = c.get("/internal/organizations", headers={"Authorization": f"Bearer {user_tok}"})
        assert r.status_code == 403
    finally:
        m.app.dependency_overrides.clear()


def test_org_admin_cannot_touch_platform_admin_account(monkeypatch):
    from backend.shared.security import create_access_token

    class Role:
        name = "admin"

    class Target:
        id = "pa-1"
        email = "pa@x.com"
        is_platform_admin = True
        is_active = True
        auth_provider = "local"
        role = Role()

    async def get_user(db, org_id, user_id):
        return Target()

    async def fake_db():
        yield None

    monkeypatch.setattr(m.services, "get_user_in_org", get_user)
    m.app.dependency_overrides[m.get_db] = fake_db
    try:
        c = TestClient(m.app)
        tok = create_access_token("org-admin-id", "admin", "org-1")
        h = {"Authorization": f"Bearer {tok}"}
        assert c.patch("/auth/organizations/org-1/users/pa-1", json={"is_active": False}, headers=h).status_code == 403
        assert c.post("/auth/organizations/org-1/users/pa-1/mfa", headers=h).status_code == 403
        assert c.post("/auth/organizations/org-1/users/pa-1/mfa/confirm", json={"totp_code": "123456"}, headers=h).status_code == 403
    finally:
        m.app.dependency_overrides.clear()


def test_auth_payload_fields_have_upper_bounds():
    """Un password de varios MB ya no llega al hash (bcrypt/passlib levantaba 500)."""
    from pydantic import ValidationError
    from app.schemas import LoginRequest, UserCreate
    with pytest.raises(ValidationError):
        LoginRequest(email="a@b.com", password="x" * 5000)
    varied = lambda n: "".join(chr(97 + (i * 7) % 26) for i in range(n))  # contrasena larga y no repetitiva
    with pytest.raises(ValidationError):
        UserCreate(email="a@b.com", password=varied(129))
    assert LoginRequest(email="a@b.com", password="x" * 1024)
    assert UserCreate(email="a@b.com", password=varied(128))
