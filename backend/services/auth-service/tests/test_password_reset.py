"""Olvide mi contrasena: link por mail de un solo uso, cambio estando adentro y link generado por un admin."""
import asyncio
import os
import re
import tempfile
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import main, password_reset, services
from backend.shared import rate_limit, security
from backend.shared.database import Base, get_db

OLD = "contrasena-vieja-1"
NEW = "contrasena-nueva-99"


@pytest.fixture()
def env(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(prefix="auth-reset-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as db:
            org = await services.create_organization(db, "Acme")
            other = await services.create_organization(db, "Otra")
            admin = await services.create_user(db, "admin@acme.com", "x" * 12, "Admin", org.id, role_name="admin")
            ana = await services.create_user(db, "ana@acme.com", OLD, "Ana", org.id, role_name="analyst")
            gus = await services.create_user(db, "gus@acme.com", OLD, "Gus", org.id, role_name="viewer")
            gus.hashed_password = None  # cuenta que entra solo con Google
            gus.auth_provider = "google"
            off = await services.create_user(db, "off@acme.com", OLD, "Off", org.id, role_name="viewer")
            off.is_active = False
            await db.commit()
            return org.id, other.id, admin.id, ana.id, gus.id

    org_id, other_id, admin_id, ana_id, gus_id = asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    class Down:  # sin Redis: contadores en memoria
        async def incr(self, *a, **k):
            raise ConnectionError()
        get = delete = expire = incr

    monkeypatch.setattr(rate_limit, "_get_redis", lambda: Down())
    rate_limit._fail_memory.clear()
    rate_limit._fallback_counts.clear()
    monkeypatch.setattr(main, "SessionLocal", Session)
    monkeypatch.setattr(services, "is_org_active", lambda org: True)  # SQLite pierde la zona horaria
    monkeypatch.setenv("FRONTEND_URL", "http://tero.local:5173")
    sent = []
    monkeypatch.setattr(password_reset, "send_reset_email", lambda to, url: sent.append((to, url)) or True)
    main.app.dependency_overrides[get_db] = override
    client = TestClient(main.app)

    def header(user_id, role, org):
        return {"Authorization": "Bearer " + security.create_access_token(user_id, role, org)}

    yield client, Session, sent, header, dict(org=org_id, other=other_id, admin=admin_id, ana=ana_id, gus=gus_id)
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def _token_from(url: str) -> str:
    return parse_qs(urlparse(url).query)["token"][0]


def _login(client, email, password):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_forgot_gives_same_answer_for_unknown_and_known_emails(env):
    client, _, sent, _, _ = env
    a = client.post("/auth/password/forgot", json={"email": "nadie@acme.com"})
    b = client.post("/auth/password/forgot", json={"email": "ana@acme.com"})
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json() == {"message": main.FORGOT_PASSWORD_MESSAGE}
    assert [to for to, _ in sent] == ["ana@acme.com"]  # solo la cuenta real recibe el mail


def test_no_mail_for_google_only_or_disabled_accounts(env):
    client, _, sent, _, _ = env
    for email in ("gus@acme.com", "off@acme.com"):
        assert client.post("/auth/password/forgot", json={"email": email}).status_code == 200
    assert sent == []


def test_full_flow_mail_link_resets_password_once(env):
    client, _, sent, _, _ = env
    client.post("/auth/password/forgot", json={"email": "ana@acme.com"})
    url = sent[0][1]
    assert url.startswith("http://tero.local:5173/restablecer?token=")
    token = _token_from(url)
    r = client.post("/auth/password/reset", json={"token": token, "new_password": NEW})
    assert r.status_code == 200
    assert _login(client, "ana@acme.com", NEW).status_code == 200
    assert _login(client, "ana@acme.com", OLD).status_code == 401
    # un solo uso: el mismo link ya no sirve
    again = client.post("/auth/password/reset", json={"token": token, "new_password": "otra-contrasena-77"})
    assert again.status_code == 400


def test_expired_and_forged_tokens_are_rejected(env):
    client, Session, _, _, ids = env

    async def user():
        async with Session() as db:
            return await services.get_user_by_id(db, ids["ana"])

    u = asyncio.run(user())
    expired = security.create_token(
        u.id, timedelta(minutes=-1), {"type": "password_reset", "pwf": password_reset.fingerprint(u.hashed_password)}
    )
    wrong_type = security.create_refresh_token(u.id)
    access = security.create_access_token(u.id, "analyst", ids["org"])
    for bad in (expired, wrong_type, access, "x" * 40):
        r = client.post("/auth/password/reset", json={"token": bad, "new_password": NEW})
        assert r.status_code == 400, bad[:20]
    assert _login(client, "ana@acme.com", OLD).status_code == 200  # nada cambio


def test_reset_token_is_not_an_access_token(env):
    client, Session, _, _, ids = env

    async def user():
        async with Session() as db:
            return await services.get_user_by_id(db, ids["ana"])

    token = password_reset.create_reset_token(asyncio.run(user()))
    r = client.get(f"/auth/organizations/{ids['org']}/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_new_password_rules(env):
    client, _, sent, _, _ = env
    client.post("/auth/password/forgot", json={"email": "ana@acme.com"})
    token = _token_from(sent[0][1])
    assert client.post("/auth/password/reset", json={"token": token, "new_password": "corta"}).status_code == 422
    assert client.post("/auth/password/reset", json={"token": token, "new_password": OLD}).status_code == 400
    assert client.post("/auth/password/reset", json={"token": token, "new_password": NEW}).status_code == 200


def test_change_password_inside_the_app(env):
    client, _, _, header, ids = env
    h = header(ids["ana"], "analyst", ids["org"])
    bad = client.post("/auth/password/change", headers=h, json={"current_password": "no-es-esa-123", "new_password": NEW})
    assert bad.status_code == 400
    same = client.post("/auth/password/change", headers=h, json={"current_password": OLD, "new_password": OLD})
    assert same.status_code == 400
    ok = client.post("/auth/password/change", headers=h, json={"current_password": OLD, "new_password": NEW})
    assert ok.status_code == 200
    assert _login(client, "ana@acme.com", NEW).status_code == 200
    assert _login(client, "ana@acme.com", OLD).status_code == 401


def test_change_password_needs_login_and_is_limited(env):
    client, _, _, header, ids = env
    assert client.post("/auth/password/change", json={"current_password": OLD, "new_password": NEW}).status_code == 401
    h = header(ids["ana"], "analyst", ids["org"])
    for _ in range(5):
        r = client.post("/auth/password/change", headers=h, json={"current_password": "mala-mala-mala1", "new_password": NEW})
        assert r.status_code == 400
    blocked = client.post("/auth/password/change", headers=h, json={"current_password": OLD, "new_password": NEW})
    assert blocked.status_code == 429


def test_google_only_account_cannot_change_password(env):
    client, _, _, header, ids = env
    r = client.post("/auth/password/change", headers=header(ids["gus"], "viewer", ids["org"]),
                    json={"current_password": OLD, "new_password": NEW})
    assert r.status_code == 400


def test_admin_generates_a_link_that_works(env):
    client, _, sent, header, ids = env
    url = f"/auth/organizations/{ids['org']}/users/{ids['ana']}/password-reset-link"
    r = client.post(url, headers=header(ids["admin"], "admin", ids["org"]))
    assert r.status_code == 200
    body = r.json()
    assert body["expires_minutes"] == 30 and "/restablecer?token=" in body["reset_url"]
    assert body["email_sent"] is False  # sin SMTP
    done = client.post("/auth/password/reset", json={"token": _token_from(body["reset_url"]), "new_password": NEW})
    assert done.status_code == 200 and _login(client, "ana@acme.com", NEW).status_code == 200


def test_admin_link_permissions_and_cases(env, monkeypatch):
    client, _, _, header, ids = env
    link = lambda uid: f"/auth/organizations/{ids['org']}/users/{uid}/password-reset-link"  # noqa: E731
    assert client.post(link(ids["ana"]), headers=header(ids["ana"], "analyst", ids["org"])).status_code == 403
    assert client.post(link(ids["ana"]), headers=header("admin-b", "admin", ids["other"])).status_code == 403
    assert client.post(link(ids["gus"]), headers=header(ids["admin"], "admin", ids["org"])).status_code == 400
    assert client.post(link("no-existe"), headers=header(ids["admin"], "admin", ids["org"])).status_code == 404
    assert client.post(link(ids["ana"])).status_code == 401


def test_admin_link_also_emails_when_smtp_is_configured(env, monkeypatch):
    client, _, sent, header, ids = env
    monkeypatch.setenv("SMTP_HOST", "smtp.local")
    r = client.post(f"/auth/organizations/{ids['org']}/users/{ids['ana']}/password-reset-link",
                    headers=header(ids["admin"], "admin", ids["org"]))
    assert r.json()["email_sent"] is True
    assert [to for to, _ in sent] == ["ana@acme.com"]


def test_forgot_is_rate_limited_per_account(env):
    client, _, sent, _, _ = env
    for _ in range(6):
        assert client.post("/auth/password/forgot", json={"email": "ana@acme.com"}).status_code == 200
    assert len(sent) == 3  # tope de 3 mails cada 15 min, sin avisar con otra respuesta


def test_reset_clears_previous_login_failures(env):
    client, _, sent, _, _ = env
    for _ in range(10):
        assert _login(client, "ana@acme.com", "mala-mala-mala1").status_code == 401
    assert _login(client, "ana@acme.com", OLD).status_code == 429  # bloqueada
    client.post("/auth/password/forgot", json={"email": "ana@acme.com"})
    token = _token_from(sent[0][1])
    assert client.post("/auth/password/reset", json={"token": token, "new_password": NEW}).status_code == 200
    assert _login(client, "ana@acme.com", NEW).status_code == 200
