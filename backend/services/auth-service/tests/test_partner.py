"""Consola multicliente (partner): aislamiento entre clientes, token acotado, marca propia y suspension."""
import asyncio
import base64
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import main, partner, services
from app.models import AuditLogEntry, Organization
from backend.shared import custody, security
from backend.shared.database import Base, get_db

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 64).decode()
GOOD_LOGO = "data:image/png;base64," + PNG


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("TERO_CUSTODY_DISABLED", "1")
    path = os.path.join(tempfile.mkdtemp(prefix="auth-partner-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with Session() as db:
            mssp = await services.create_organization(db, "Defensa SA")
            mssp.is_partner = True
            other_mssp = await services.create_organization(db, "Otro MSSP")
            other_mssp.is_partner = True
            plain = await services.create_organization(db, "Empresa comun")
            a = await services.create_user(db, "admin@mssp.com", "x" * 12, "Admin MSSP", mssp.id, role_name="admin")
            an = await services.create_user(db, "analyst@mssp.com", "x" * 12, "Analista", mssp.id, role_name="analyst")
            vi = await services.create_user(db, "viewer@mssp.com", "x" * 12, "Viewer", mssp.id, role_name="viewer")
            oa = await services.create_user(db, "admin@otro.com", "x" * 12, "Admin otro", other_mssp.id, role_name="admin")
            pa = await services.create_user(db, "admin@comun.com", "x" * 12, "Admin comun", plain.id, role_name="admin")
            await db.commit()
            return dict(mssp=mssp.id, other=other_mssp.id, plain=plain.id, admin=a.id, analyst=an.id, viewer=vi.id,
                        other_admin=oa.id, plain_admin=pa.id)

    ids = asyncio.run(setup())

    async def override():
        async with Session() as session:
            yield session

    main.app.dependency_overrides[get_db] = override
    client = TestClient(main.app)

    def hdr(user_id, role, org, email=None):
        return {"Authorization": "Bearer " + security.create_access_token(user_id, role, org, False, email=email)}

    yield client, Session, ids, hdr
    main.app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def _create(client, h, name="Cliente Uno", **extra):
    return client.post("/auth/partner/clients", headers=h, json={"name": name, **extra})


def test_partner_creates_and_lists_clients_only_its_own(env):
    client, _, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"], "admin@mssp.com")
    r = _create(client, h, "Cliente Uno", admin_email="ti@cliente1.com", admin_password="Clave-Segura-123", admin_full_name="TI")
    assert r.status_code == 201, r.text
    c1 = r.json()
    assert c1["users"] == 1 and c1["is_active"]
    assert _create(client, h, "Cliente Dos").status_code == 201
    other = hdr(ids["other_admin"], "admin", ids["other"], "admin@otro.com")
    assert _create(client, other, "Cliente de otro").status_code == 201
    mine = client.get("/auth/partner/clients", headers=h).json()["items"]
    assert sorted(c["name"] for c in mine) == ["Cliente Dos", "Cliente Uno"]
    theirs = client.get("/auth/partner/clients", headers=other).json()["items"]
    assert [c["name"] for c in theirs] == ["Cliente de otro"]


def test_client_inherits_partner_subscription(env):
    client, Session, ids, hdr = env
    r = _create(client, hdr(ids["admin"], "admin", ids["mssp"]))

    async def read():
        async with Session() as db:
            m = await services.get_organization_by_id(db, ids["mssp"])
            c = await services.get_organization_by_id(db, r.json()["id"])
            return m.subscription_expires_at, c.subscription_expires_at, c.parent_org_id
    mexp, cexp, parent = asyncio.run(read())
    assert mexp == cexp and parent == ids["mssp"]


def test_only_admin_creates_and_plain_org_is_not_partner(env):
    client, _, ids, hdr = env
    assert _create(client, hdr(ids["analyst"], "analyst", ids["mssp"])).status_code == 403
    assert _create(client, hdr(ids["plain_admin"], "admin", ids["plain"])).status_code == 403
    assert client.get("/auth/partner/clients", headers=hdr(ids["plain_admin"], "admin", ids["plain"])).status_code == 403
    assert _create(client, hdr(ids["admin"], "admin", ids["mssp"]), name="x").status_code == 422  # nombre muy corto
    assert _create(client, hdr(ids["admin"], "admin", ids["mssp"]), admin_email="a@b.com").status_code == 422  # email sin clave


def test_duplicate_admin_email_rejected_and_weak_password(env):
    client, _, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"])
    assert _create(client, h, admin_email="admin@mssp.com", admin_password="Clave-Segura-123").status_code == 400
    assert _create(client, h, admin_email="nuevo@x.com", admin_password="corta").status_code == 422


def test_enter_client_issues_short_limited_token_and_audits(env):
    client, Session, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"], "admin@mssp.com")
    cid = _create(client, h).json()["id"]
    r = client.post(f"/auth/partner/clients/{cid}/enter", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    claims = security.decode_token(body["access_token"])
    assert claims["org_id"] == cid and claims["partner_org_id"] == ids["mssp"]
    assert claims["role"] == "soc_manager"  # un admin del partner NUNCA es admin del cliente
    assert claims["type"] == "access" and not claims.get("platform_admin")
    assert claims["email"] == "admin@mssp.com" and claims["sub"] == ids["admin"]
    assert 0 < claims["exp"] - claims["iat"] <= 240 * 60
    assert "refresh_token" not in body

    async def audit():
        async with Session() as db:
            rows = (await db.execute(select(AuditLogEntry).where(AuditLogEntry.action == "partner.enter_client"))).scalars().all()
            return [(e.actor_email, e.resource) for e in rows]
    assert asyncio.run(audit()) == [("admin@mssp.com", cid)]


def test_enter_role_is_capped_by_role_in_partner(env):
    client, _, ids, hdr = env
    cid = _create(client, hdr(ids["admin"], "admin", ids["mssp"])).json()["id"]
    for uid, role, expected in ((ids["analyst"], "analyst", "analyst"), (ids["viewer"], "viewer", "viewer")):
        r = client.post(f"/auth/partner/clients/{cid}/enter", headers=hdr(uid, role, ids["mssp"], f"{role}@mssp.com"))
        assert r.status_code == 200 and security.decode_token(r.json()["access_token"])["role"] == expected


def test_cannot_enter_foreign_or_unknown_client(env):
    client, _, ids, hdr = env
    mine = hdr(ids["admin"], "admin", ids["mssp"])
    other = hdr(ids["other_admin"], "admin", ids["other"])
    foreign = _create(client, other, "Ajeno").json()["id"]
    assert client.post(f"/auth/partner/clients/{foreign}/enter", headers=mine).status_code == 404
    assert client.post(f"/auth/partner/clients/{ids['plain']}/enter", headers=mine).status_code == 404  # org comun, sin padre
    assert client.post(f"/auth/partner/clients/{ids['other']}/enter", headers=mine).status_code == 404  # otro partner
    assert client.post("/auth/partner/clients/nope/enter", headers=mine).status_code == 404
    assert client.patch(f"/auth/partner/clients/{foreign}", headers=mine, json={"name": "Hackeado"}).status_code == 404
    assert client.patch(f"/auth/partner/clients/{foreign}", headers=mine, json={"is_active": False}).status_code == 404


def test_entered_token_cannot_use_partner_console_or_chain(env):
    client, _, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"], "admin@mssp.com")
    c1 = _create(client, h, "Uno").json()["id"]
    c2 = _create(client, h, "Dos").json()["id"]
    tok = {"Authorization": "Bearer " + client.post(f"/auth/partner/clients/{c1}/enter", headers=h).json()["access_token"]}
    assert client.get("/auth/partner/clients", headers=tok).status_code == 403
    assert client.post(f"/auth/partner/clients/{c2}/enter", headers=tok).status_code == 403
    assert _create(client, tok, "Tres").status_code == 403
    assert client.put("/auth/partner/brand", headers=tok, json={"name": "X"}).status_code == 403


def test_forged_partner_claim_does_not_help(env):
    """Un token con partner_org_id inventado pero de una org comun no habilita nada: la org se mira en la base."""
    client, _, ids, hdr = env
    forged = {"Authorization": "Bearer " + security.create_token(
        ids["plain_admin"], timedelta(minutes=5), {"role": "admin", "type": "access", "org_id": ids["plain"]})}
    assert client.get("/auth/partner/clients", headers=forged).status_code == 403


def test_suspended_client_blocks_enter_and_login_paths(env):
    client, Session, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"])
    cid = _create(client, h, admin_email="ti@c.com", admin_password="Clave-Segura-123").json()["id"]
    assert client.patch(f"/auth/partner/clients/{cid}", headers=h, json={"is_active": False}).status_code == 200
    assert client.post(f"/auth/partner/clients/{cid}/enter", headers=h).status_code == 403
    r = client.post("/auth/login", json={"email": "ti@c.com", "password": "Clave-Segura-123"})
    assert r.status_code == 403 and "suspendida" in r.text
    assert client.patch(f"/auth/partner/clients/{cid}", headers=h, json={"is_active": True}).status_code == 200
    assert client.post(f"/auth/partner/clients/{cid}/enter", headers=h).status_code == 200
    assert client.post("/auth/login", json={"email": "ti@c.com", "password": "Clave-Segura-123"}).status_code == 200


def test_client_blocked_when_partner_subscription_expires(env):
    client, Session, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"])
    cid = _create(client, h, admin_email="ti@c.com", admin_password="Clave-Segura-123").json()["id"]

    async def expire():
        async with Session() as db:
            m = await services.get_organization_by_id(db, ids["mssp"])
            m.subscription_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            await db.commit()
    asyncio.run(expire())
    assert client.post(f"/auth/partner/clients/{cid}/enter", headers=h).status_code == 402
    assert client.post("/auth/login", json={"email": "ti@c.com", "password": "Clave-Segura-123"}).status_code == 402


def test_only_platform_admin_toggles_partner_and_guards(env):
    client, _, ids, hdr = env
    padmin = {"Authorization": "Bearer " + security.create_access_token("pa", "admin", ids["mssp"], True)}
    assert client.put(f"/auth/organizations/{ids['plain']}/partner", headers=hdr(ids["plain_admin"], "admin", ids["plain"]), json={"is_partner": True}).status_code == 403
    assert client.put(f"/auth/organizations/{ids['plain']}/partner", headers=padmin, json={"is_partner": True}).status_code == 200
    cid = _create(client, hdr(ids["admin"], "admin", ids["mssp"])).json()["id"]
    assert client.put(f"/auth/organizations/{cid}/partner", headers=padmin, json={"is_partner": True}).status_code == 409  # un cliente no es partner
    assert client.put(f"/auth/organizations/{ids['mssp']}/partner", headers=padmin, json={"is_partner": False}).status_code == 409  # tiene clientes
    assert client.put(f"/auth/organizations/{ids['other']}/partner", headers=padmin, json={"is_partner": False}).status_code == 200


def test_brand_validation(env):
    client, _, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"])
    assert client.put("/auth/partner/brand", headers=h, json={"name": "Defensa", "color": "#1A73E8", "logo": GOOD_LOGO}).status_code == 200
    bad = [
        {"color": "rojo"}, {"color": "#12345"}, {"color": "#12345g"},
        {"logo": "data:image/svg+xml;base64," + base64.b64encode(b"<svg onload=alert(1)>").decode()},
        {"logo": "data:image/png;base64," + base64.b64encode(b"<html>no soy png</html>").decode()},
        {"logo": "data:image/jpeg;base64," + PNG},  # dice jpeg pero es png
        {"logo": "https://evil.example/logo.png"},
        {"logo": "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * (partner.LOGO_MAX_BYTES + 1)).decode()},
        {"logo": "data:image/png;base64,@@@"},
    ]
    for b in bad:
        r = client.put("/auth/partner/brand", headers=h, json={"name": "X", **b})
        assert r.status_code in (422,), (b, r.status_code)
    assert client.put("/auth/partner/brand", headers=h, json={"name": "A" * 61}).status_code == 422
    assert client.put("/auth/partner/brand", headers=hdr(ids["analyst"], "analyst", ids["mssp"]), json={"name": "X"}).status_code == 403
    r = client.put("/auth/partner/brand", headers=h, json={"name": "Mi <b>marca</b>"})
    assert r.json()["name"] == "Mi bmarca/b"  # sin < ni >


def test_clients_use_partner_brand_unless_they_have_their_own(env):
    client, Session, ids, hdr = env
    h = hdr(ids["admin"], "admin", ids["mssp"])
    client.put("/auth/partner/brand", headers=h, json={"name": "Defensa", "color": "#112233", "logo": GOOD_LOGO})
    cid = _create(client, h, "Uno", admin_email="ti@c.com", admin_password="Clave-Segura-123").json()["id"]
    child = {"Authorization": "Bearer " + security.create_access_token("u", "admin", cid, False)}
    b = client.get("/auth/brand", headers=child).json()
    assert b["name"] == "Defensa" and b["color"] == "#112233" and b["logo"] == GOOD_LOGO and not b["is_partner"]
    mine = client.get("/auth/brand", headers=h).json()
    assert mine["is_partner"] and not mine["acting_for_partner"]
    entered = {"Authorization": "Bearer " + client.post(f"/auth/partner/clients/{cid}/enter", headers=h).json()["access_token"]}
    e = client.get("/auth/brand", headers=entered).json()
    assert e["acting_for_partner"] and not e["is_partner"] and e["name"] == "Defensa"
    plain = client.get("/auth/brand", headers=hdr(ids["plain_admin"], "admin", ids["plain"])).json()
    assert plain["name"] == "" and plain["logo"] == "" and not plain["is_partner"]
    other = client.get("/auth/brand", headers=hdr(ids["other_admin"], "admin", ids["other"])).json()
    assert other["name"] == ""  # la marca de un partner no se filtra a otro


def test_internal_endpoints_require_service_token(env):
    client, _, ids, hdr = env
    user = hdr(ids["admin"], "admin", ids["mssp"])
    svc = {"Authorization": "Bearer " + security.create_access_token("system:case-service", "admin", ids["mssp"])}
    assert client.get(f"/internal/organizations/{ids['mssp']}/brand", headers=user).status_code == 403
    assert client.get(f"/internal/partners/{ids['mssp']}/clients", headers=user).status_code == 403
    assert client.get(f"/internal/organizations/{ids['mssp']}/brand", headers=svc).status_code == 200
    assert client.get(f"/internal/partners/{ids['plain']}/clients", headers=svc).status_code == 404
    _create(client, user, "Uno")
    items = client.get(f"/internal/partners/{ids['mssp']}/clients", headers=svc).json()["items"]
    assert [c["name"] for c in items] == ["Uno"]
    assert "hashed_password" not in str(items)
    info = client.get(f"/internal/organizations/{ids['mssp']}", headers=svc).json()
    assert info["is_partner"] is True and info["parent_org_id"] is None


def test_max_clients_limit(env, monkeypatch):
    client, _, ids, hdr = env
    monkeypatch.setattr(partner, "MAX_CLIENTS", 2)
    h = hdr(ids["admin"], "admin", ids["mssp"])
    assert _create(client, h, "Uno").status_code == 201
    assert _create(client, h, "Dos").status_code == 201
    assert _create(client, h, "Tres").status_code == 409
