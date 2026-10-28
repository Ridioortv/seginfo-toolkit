"""Consola multicliente (MSSP / partner): una organizacion que administra a otras, con marca propia.

Modelo (a proposito simple, para que el aislamiento entre tenants siga siendo el de siempre):

  * Un PARTNER es una organizacion con is_partner=True (solo un administrador de plataforma lo habilita). Sus CLIENTES son
    organizaciones comunes con parent_org_id = el partner. Un solo nivel: un cliente no puede ser partner y un partner
    no puede ser cliente de otro.
  * El partner NO ve los datos de sus clientes "por transparencia": entra a un cliente con POST /auth/partner/clients/{id}/enter,
    que emite un token CORTO (60 min por defecto, sin refresh) con la organizacion del cliente y un rol recortado (nunca
    admin: un administrador del partner entra como soc_manager). El token lleva `partner_org_id` y quien entro; con ese
    claim no se puede volver a entrar a otro cliente ni usar la consola de partner. Cada ingreso queda en el registro de
    auditoria encadenado de auth-service Y en la cadena de custodia del propio cliente (evento partner.access), que el
    cliente puede ver.
  * Un cliente solo existe para su partner: todas las rutas /auth/partner/clients/{id}/... comprueban parent_org_id contra la
    organizacion del token, nunca contra un dato que mande quien llama.
  * La suscripcion se paga una vez: los clientes estan activos mientras lo este su partner (ver services.org_active).
  * Marca propia: nombre (<=60), color #RRGGBB y logo PNG/JPEG (<=150 KB, se verifica la firma del archivo; SVG no se acepta
    porque puede llevar scripts). Un cliente sin marca propia usa la de su partner."""
from __future__ import annotations

import base64
import binascii
import os
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody
from backend.shared.database import get_db
from backend.shared.rate_limit import check_rate_limit
from backend.shared.security import create_token
from app import services
from app.dependencies import get_current_claims, require_platform_admin, require_service_token
from app.models import Organization, User
from app.schemas import NormEmail, StrongPassword

router = APIRouter()

MAX_CLIENTS = int(os.getenv("PARTNER_MAX_CLIENTS", "500"))
ENTER_MINUTES = max(5, min(int(os.getenv("PARTNER_ENTER_TOKEN_MINUTES", "60")), 240))
LOGO_MAX_BYTES = 150 * 1024
# Rol con el que se entra a un cliente segun el rol que se tiene en el partner: nunca admin del cliente.
ENTER_ROLE = {"admin": "soc_manager", "soc_manager": "soc_manager", "analyst": "analyst", "viewer": "viewer"}
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_LOGO = re.compile(r"^data:image/(png|jpeg);base64,([A-Za-z0-9+/=]+)$")
_CTRL = re.compile(r"[\x00-\x1f\x7f<>]")


# ----------------------------- marca -----------------------------

class BrandError(ValueError):
    pass


def clean_brand(name: str | None, color: str | None, logo: str | None) -> dict:
    name = _CTRL.sub("", (name or "")).strip()
    if len(name) > 60:
        raise BrandError("El nombre de la marca puede tener hasta 60 caracteres")
    color = (color or "").strip()
    if color and not _COLOR.match(color):
        raise BrandError("El color tiene que ser del tipo #1a73e8")
    logo = (logo or "").strip()
    if logo:
        m = _LOGO.match(logo)
        if not m:
            raise BrandError("El logo tiene que ser una imagen PNG o JPEG")
        try:
            raw = base64.b64decode(m.group(2), validate=True)
        except (binascii.Error, ValueError):
            raise BrandError("El logo no es una imagen valida")
        if len(raw) > LOGO_MAX_BYTES:
            raise BrandError("El logo pesa mas de 150 KB")
        is_png = m.group(1) == "png" and raw.startswith(b"\x89PNG\r\n\x1a\n")
        is_jpg = m.group(1) == "jpeg" and raw.startswith(b"\xff\xd8\xff")
        if not (is_png or is_jpg):
            raise BrandError("El logo no es una imagen PNG o JPEG valida")
    return {"name": name, "color": color.lower(), "logo": logo}


async def effective_brand(db: AsyncSession, org: Organization | None) -> dict:
    """Marca que se ve en una organizacion: la propia si la tiene; si no, la de su partner; si no, vacia (la de TERO)."""
    for candidate in (org, await services.get_organization_by_id(db, org.parent_org_id) if org is not None and org.parent_org_id else None):
        if candidate is not None and (candidate.brand_name or candidate.brand_logo or candidate.brand_color):
            return {"name": candidate.brand_name, "color": candidate.brand_color, "logo": candidate.brand_logo}
    return {"name": "", "color": "", "logo": ""}


# ----------------------------- esquemas -----------------------------

class ClientCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    # Opcional: el primer usuario administrador del PROPIO cliente (su gente). Sin esto, el cliente solo se opera desde el partner.
    admin_email: NormEmail | None = None
    admin_full_name: str = Field("", max_length=255)
    admin_password: StrongPassword | None = None


class ClientUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=100)
    is_active: bool | None = None


class BrandIn(BaseModel):
    name: str = Field("", max_length=60)
    color: str = Field("", max_length=7)
    logo: str = Field("", max_length=300_000)


class PartnerFlag(BaseModel):
    is_partner: bool


# ----------------------------- helpers -----------------------------

async def partner_org(claims: dict, db: AsyncSession) -> Organization:
    """La organizacion partner de quien llama; si el token es de alguien que "entro" a un cliente, no vale."""
    if claims.get("partner_org_id"):
        raise HTTPException(status_code=403, detail="Volve a tu consola de partner para hacer esto")
    org = await services.get_organization_by_id(db, claims.get("org_id") or "")
    if org is None or not org.is_partner:
        raise HTTPException(status_code=403, detail="Tu organizacion no es un partner")
    return org


def _require_admin(claims: dict) -> None:
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Permisos insuficientes")


async def _client(db: AsyncSession, partner: Organization, client_id: str) -> Organization:
    # el filtro por parent_org_id es lo que impide tocar a un cliente ajeno
    result = await db.execute(select(Organization).where(Organization.id == client_id, Organization.parent_org_id == partner.id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    return org


def client_view(org: Organization, users: int = 0) -> dict:
    return {
        "id": org.id, "name": org.name, "slug": org.slug, "is_active": org.is_active, "users": users,
        "created_at": org.created_at.isoformat() if org.created_at else None,
        "subscription_expires_at": org.subscription_expires_at.isoformat() if org.subscription_expires_at else None,
    }


async def _user_counts(db: AsyncSession, org_ids: list[str]) -> dict[str, int]:
    if not org_ids:
        return {}
    rows = await db.execute(select(User.organization_id, func.count(User.id)).where(
        User.organization_id.in_(org_ids), User.is_active.is_(True)).group_by(User.organization_id))
    return {oid: n for oid, n in rows.all()}


async def list_clients(db: AsyncSession, partner: Organization) -> list[dict]:
    rows = (await db.execute(select(Organization).where(Organization.parent_org_id == partner.id).order_by(Organization.name))).scalars().all()
    counts = await _user_counts(db, [o.id for o in rows])
    return [client_view(o, counts.get(o.id, 0)) for o in rows]


# ----------------------------- rutas del partner -----------------------------

@router.get("/auth/partner/clients")
async def get_clients(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    partner = await partner_org(claims, db)
    return {"items": await list_clients(db, partner), "max_clients": MAX_CLIENTS}


@router.post("/auth/partner/clients", status_code=201)
async def create_client(payload: ClientCreate, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    _require_admin(claims)
    partner = await partner_org(claims, db)
    if bool(payload.admin_email) != bool(payload.admin_password):
        raise HTTPException(status_code=422, detail="Para crear un administrador del cliente hacen falta su email y su contrasena")
    count = (await db.execute(select(func.count(Organization.id)).where(Organization.parent_org_id == partner.id))).scalar_one()
    if count >= MAX_CLIENTS:
        raise HTTPException(status_code=409, detail=f"Llegaste al maximo de {MAX_CLIENTS} clientes")
    if payload.admin_email and await services.get_user_by_email(db, payload.admin_email):
        raise HTTPException(status_code=400, detail="El email ya esta registrado")
    org = await services.create_organization(db, payload.name.strip())
    org.parent_org_id = partner.id
    org.subscription_expires_at = partner.subscription_expires_at
    users = 0
    if payload.admin_email and payload.admin_password:
        await services.create_user(db, payload.admin_email, payload.admin_password, payload.admin_full_name, org.id, role_name="admin")
        users = 1
    await services.record_audit_event(db, claims.get("email") or claims.get("sub", ""), "partner.client.create", org.id)
    await db.commit()
    await db.refresh(org)
    return client_view(org, users)


@router.patch("/auth/partner/clients/{client_id}")
async def update_client(client_id: str, payload: ClientUpdate, claims: dict = Depends(get_current_claims),
                        db: AsyncSession = Depends(get_db)):
    _require_admin(claims)
    partner = await partner_org(claims, db)
    org = await _client(db, partner, client_id)
    if payload.name is None and payload.is_active is None:
        raise HTTPException(status_code=422, detail="No hay nada para cambiar")
    if payload.name is not None:
        org.name = payload.name.strip()
    if payload.is_active is not None and payload.is_active != org.is_active:
        org.is_active = payload.is_active
        await services.record_audit_event(db, claims.get("email") or claims.get("sub", ""),
                                          "partner.client.reactivate" if payload.is_active else "partner.client.suspend", org.id)
    await db.commit()
    await db.refresh(org)
    return client_view(org, (await _user_counts(db, [org.id])).get(org.id, 0))


@router.post("/auth/partner/clients/{client_id}/enter")
async def enter_client(client_id: str, request: Request, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    partner = await partner_org(claims, db)
    if not await check_rate_limit(f"partner_enter:{claims.get('sub')}", 60, 300):
        raise HTTPException(status_code=429, detail="Demasiados ingresos seguidos; espera unos minutos")
    org = await _client(db, partner, client_id)
    if not org.is_active:
        raise HTTPException(status_code=403, detail="Este cliente esta suspendido")
    if not await services.org_active(db, org):
        raise HTTPException(status_code=402, detail="La suscripcion esta vencida")
    role = ENTER_ROLE.get(claims.get("role", ""))
    if role is None:
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    email = claims.get("email") or ""
    # primero el registro de auditoria (si falla, no hay token); despues, la custodia del cliente (mejor esfuerzo, con cola)
    await services.record_audit_event(db, email or claims.get("sub", ""), "partner.enter_client", org.id)
    await db.commit()
    await custody.record_event(
        "partner.access", service="auth-service", organization_id=org.id, actor=email or claims.get("sub", ""),
        subject_type="organization", subject_id=org.id,
        payload={"partner": partner.name, "partner_org_id": partner.id, "user": email, "role_in_client": role, "minutes": ENTER_MINUTES},
    )
    extra = {"role": role, "type": "access", "org_id": org.id, "partner_org_id": partner.id, "acting": True}
    if email:
        extra["email"] = email
    token = create_token(claims["sub"], timedelta(minutes=ENTER_MINUTES), extra)
    return {"access_token": token, "expires_in": ENTER_MINUTES * 60, "role": role, "client": {"id": org.id, "name": org.name}}


# ----------------------------- marca -----------------------------

@router.get("/auth/brand")
async def get_brand(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    """Marca que tiene que mostrar la interfaz a quien llama, y si su organizacion es un partner."""
    org = await services.get_organization_by_id(db, claims.get("org_id") or "") if claims.get("org_id") else None
    out = await effective_brand(db, org)
    out["is_partner"] = bool(org and org.is_partner) and not claims.get("partner_org_id")
    out["acting_for_partner"] = bool(claims.get("partner_org_id"))
    out["organization_name"] = org.name if org else ""
    return out


@router.put("/auth/partner/brand")
async def put_brand(payload: BrandIn, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    _require_admin(claims)
    partner = await partner_org(claims, db)
    try:
        brand = clean_brand(payload.name, payload.color, payload.logo)
    except BrandError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    partner.brand_name, partner.brand_color, partner.brand_logo = brand["name"], brand["color"], brand["logo"]
    await services.record_audit_event(db, claims.get("email") or claims.get("sub", ""), "partner.brand.update", partner.id)
    await db.commit()
    return brand


@router.put("/auth/organizations/{org_id}/partner")
async def set_partner(org_id: str, payload: PartnerFlag, claims: dict = Depends(require_platform_admin),
                      db: AsyncSession = Depends(get_db)):
    """Solo un administrador de plataforma habilita (o quita) el rol de partner de una organizacion."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if payload.is_partner and org.parent_org_id:
        raise HTTPException(status_code=409, detail="Esta organizacion es cliente de un partner; no puede ser partner")
    if not payload.is_partner:
        n = (await db.execute(select(func.count(Organization.id)).where(Organization.parent_org_id == org.id))).scalar_one()
        if n:
            raise HTTPException(status_code=409, detail=f"Tiene {n} cliente(s); quitale o reasignale los clientes primero")
    org.is_partner = payload.is_partner
    await services.record_audit_event(db, claims.get("sub", ""), "organization.partner." + ("on" if payload.is_partner else "off"), org.id)
    await db.commit()
    return {"id": org.id, "is_partner": org.is_partner}


# ----------------------------- servicio a servicio -----------------------------

@router.get("/internal/organizations/{org_id}/brand")
async def internal_brand(org_id: str, claims: dict = Depends(require_service_token), db: AsyncSession = Depends(get_db)):
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    return await effective_brand(db, org)


@router.get("/internal/partners/{partner_id}/clients")
async def internal_clients(partner_id: str, claims: dict = Depends(require_service_token), db: AsyncSession = Depends(get_db)):
    partner = await services.get_organization_by_id(db, partner_id)
    if partner is None or not partner.is_partner:
        raise HTTPException(status_code=404, detail="No es un partner")
    return {"partner": {"id": partner.id, "name": partner.name}, "items": await list_clients(db, partner)}
