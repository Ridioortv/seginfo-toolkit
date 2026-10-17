"""El callback OIDC exige la cookie puesta en /login (login-CSRF) y no entra por
SSO a cuentas de platform_admin."""
from fastapi.testclient import TestClient
import app.main as m
from app.main import _OIDC_BIND_COOKIE


class _Org:
    id = "org-1"
    slug = "acme"


class _Cfg:
    enabled = True
    issuer = "https://idp.example"
    client_id = "cid"
    default_role = "viewer"


def _patch(monkeypatch):
    async def get_org(db, slug):
        return _Org()

    async def get_cfg(db, org_id):
        return _Cfg()

    monkeypatch.setattr(m.services, "get_organization_by_slug", get_org)
    monkeypatch.setattr(m.services, "get_sso_config", get_cfg)

    async def authorize(config, redirect_uri, state, nonce):
        return "https://idp.example/authorize"

    monkeypatch.setattr(m.oidc, "build_authorize_url", authorize)

    async def fake_db():
        yield None

    m.app.dependency_overrides[m.get_db] = fake_db


def test_login_sets_bind_cookie_and_callback_without_it_is_rejected(monkeypatch):
    _patch(monkeypatch)
    try:
        c = TestClient(m.app, follow_redirects=False)
        r = c.get("/auth/oidc/acme/login")
        assert r.status_code in (302, 307)
        assert _OIDC_BIND_COOKIE in r.headers.get("set-cookie", "")
        state = m.create_token("org-1", m.timedelta(minutes=5), {"type": "oidc_state", "nonce": "n1"})
        attacker = TestClient(m.app, follow_redirects=False)  # navegador de la victima: sin cookie
        r2 = attacker.get(f"/auth/oidc/acme/callback?code=x&state={state}")
        assert r2.status_code == 401
    finally:
        m.app.dependency_overrides.clear()


def test_login_rejects_malformed_client_state(monkeypatch):
    _patch(monkeypatch)
    try:
        c = TestClient(m.app, follow_redirects=False)
        assert c.get("/auth/oidc/acme/login?cs=%3Cscript%3E").status_code == 422
        assert c.get("/auth/oidc/acme/login?cs=short").status_code == 422
        assert c.get("/auth/oidc/acme/login?cs=" + "a" * 32).status_code in (302, 307)
    finally:
        m.app.dependency_overrides.clear()


def test_client_state_travels_in_state_and_is_echoed_in_callback_fragment(monkeypatch):
    """La SPA compara el cs del fragmento con el que guardo en sessionStorage:
    un link /sso/callback#access_token=... armado a mano no lo tiene."""
    _patch(monkeypatch)
    seen = {}

    async def authorize(config, redirect_uri, state, nonce):
        seen["state"], seen["nonce"] = state, nonce
        return "https://idp.example/authorize"

    async def exchange(config, code, redirect_uri):
        return {"id_token": "t"}

    async def validate(config, id_token, nonce):
        return {"email": "u@acme.com", "name": "U"}

    class _U:
        is_active = True
        is_platform_admin = False
        organization_id = "org-1"
        role = None

    async def get_user(db, email, name, org, role):
        return _U()

    async def noop(*a, **k):
        return None

    class _Db:
        async def commit(self):
            pass

    async def fake_db():
        yield _Db()

    monkeypatch.setattr(m.oidc, "build_authorize_url", authorize)
    monkeypatch.setattr(m.oidc, "exchange_code", exchange)
    monkeypatch.setattr(m.oidc, "validate_id_token", validate)
    monkeypatch.setattr(m.services, "get_or_create_oidc_user", get_user)
    monkeypatch.setattr(m.services, "issue_tokens", lambda user, role: ("ACCESS", "REFRESH"))
    monkeypatch.setattr(m.services, "record_audit_event", noop)
    monkeypatch.setattr(m, "_reject_if_org_inactive", noop)
    m.app.dependency_overrides[m.get_db] = fake_db
    try:
        c = TestClient(m.app, follow_redirects=False)
        cs = "abcdEFGH12345678-_xy"
        c.get(f"/auth/oidc/acme/login?cs={cs}")
        r = c.get(f"/auth/oidc/acme/callback?code=x&state={seen['state']}")
        assert r.status_code in (302, 307)
        loc = r.headers["location"]
        assert "access_token=ACCESS" in loc and f"cs={cs}" in loc
    finally:
        m.app.dependency_overrides.clear()
