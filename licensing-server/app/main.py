"""Servidor central de licencias de SentinelOps.

Este servicio NO se distribuye a los clientes (no va dentro del .rar) --
lo aloja el operador (ver licensing-server/README.md para donde y como
desplegarlo) y es la fuente de verdad de que organizacion tiene la
suscripcion al dia. Cada instalacion on-prem de un cliente (su
auth-service) lo consulta periodicamente via backend/shared/license_check.py
y cachea localmente la respuesta -- ver el razonamiento completo en ese
modulo y en Organization.subscription_expires_at (backend/services/auth-service/app/models.py).

Autenticacion: los endpoints /admin/* (crear/extender/revocar un
cliente) requieren `Authorization: Bearer <ADMIN_TOKEN>` -- son para uso
exclusivo del operador (hoy a mano; el dia que se conecte el webhook de
Mercado Pago, ese webhook le pega a estos mismos endpoints). El endpoint
/license/{license_key}/status es publico a proposito: cualquier
instalacion on-prem necesita poder consultarlo sin credenciales previas
mas que su propia license_key, y la respuesta viene firmada (nunca
autenticada por sesion) para que ningun intermediario pueda alterarla
sin que el cliente lo detecte."""
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, Field

from app import db
from app.signing import sign_payload

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DEFAULT_PERIOD_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ADMIN_TOKEN:
        raise RuntimeError(
            "ADMIN_TOKEN no esta configurado -- sin esto, los endpoints /admin/* "
            "(crear/extender licencias) quedarian abiertos a cualquiera. Setealo "
            "antes de arrancar (ver licensing-server/README.md)."
        )
    db.init_db()
    yield


app = FastAPI(title="SentinelOps Licensing Server", version="0.1.0", lifespan=lifespan)


def require_admin(authorization: str = Header(default="")) -> None:
    token = authorization.removeprefix("Bearer ").strip()
    # compare_digest (no ==) para no filtrar el largo del token via timing.
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Token de administrador invalido")


@app.get("/health")
def health():
    return {"status": "ok", "service": "licensing-server"}


class ClientCreate(BaseModel):
    org_name: str = Field(..., min_length=1)
    license_key: str | None = Field(default=None, description="Si se omite, se genera uno random")
    days: int = Field(default=DEFAULT_PERIOD_DAYS, ge=1)
    notes: str = ""


class ClientOut(BaseModel):
    license_key: str
    org_name: str
    subscription_expires_at: str
    notes: str
    created_at: str


class ExtendRequest(BaseModel):
    days: int = Field(default=DEFAULT_PERIOD_DAYS, ge=1)


@app.post("/admin/clients", response_model=ClientOut, status_code=status.HTTP_201_CREATED)
def create_client(payload: ClientCreate, _: None = Depends(require_admin)):
    license_key = payload.license_key or secrets.token_urlsafe(24)
    if db.get_client(license_key) is not None:
        raise HTTPException(status_code=400, detail="Esa license_key ya existe")
    expires_at = (_now() + timedelta(days=payload.days)).isoformat()
    db.create_client(license_key, payload.org_name, expires_at, payload.notes)
    row = db.get_client(license_key)
    return ClientOut(**dict(row))


@app.get("/admin/clients", response_model=list[ClientOut])
def list_clients(_: None = Depends(require_admin)):
    return [ClientOut(**dict(row)) for row in db.list_clients()]


@app.post("/admin/clients/{license_key}/extend", response_model=ClientOut)
def extend_client(license_key: str, payload: ExtendRequest, _: None = Depends(require_admin)):
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    current_expiry = datetime.fromisoformat(row["subscription_expires_at"])
    # Se extiende desde la fecha de vencimiento ACTUAL (nunca desde "ahora"),
    # asi que renovar unos dias antes de que venza no le hace perder al
    # cliente los dias que le quedaban. Si ya esta vencida, arranca de
    # nuevo desde ahora (si no, un cliente que dejo de pagar hace 6 meses
    # y renueva hoy quedaria "vencido" igual, sumando 30 dias a una fecha
    # ya vieja en vez de tener 30 dias reales desde hoy).
    base = max(current_expiry, _now())
    new_expiry = (base + timedelta(days=payload.days)).isoformat()
    db.set_expiry(license_key, new_expiry)
    row = db.get_client(license_key)
    return ClientOut(**dict(row))


@app.post("/admin/clients/{license_key}/revoke", response_model=ClientOut)
def revoke_client(license_key: str, _: None = Depends(require_admin)):
    """Corta el acceso YA (pone subscription_expires_at = ahora) -- para
    fraude/chargebacks, no para el vencimiento normal de fin de mes (eso
    ya lo maneja is_org_active() solo, sin tocar este endpoint)."""
    row = db.get_client(license_key)
    if row is None:
        raise HTTPException(status_code=404, detail="license_key desconocida")
    db.set_expiry(license_key, _now().isoformat())
    row = db.get_client(license_key)
    return ClientOut(**dict(row))


@app.get("/license/{license_key}/status")
def license_status(license_key: str, response: Response):
    row = db.get_client(license_key)
    now = _now()
    if row is None:
        payload = {"license_key": license_key, "valid": False, "valid_until": None, "checked_at": now.isoformat()}
    else:
        expires_at = datetime.fromisoformat(row["subscription_expires_at"])
        payload = {
            "license_key": license_key,
            "valid": expires_at > now,
            "valid_until": row["subscription_expires_at"],
            "checked_at": now.isoformat(),
        }
    # La firma va en un header (no en el body) para que el body siga
    # siendo JSON plano y facil de loguear/debuggear -- el cliente
    # (backend/shared/license_check.py) lee X-Signature y verifica sobre
    # el body ya parseado con la misma codificacion canonica.
    response.headers["X-Signature"] = sign_payload(payload)
    return payload
