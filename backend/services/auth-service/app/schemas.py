"""Pydantic request/response schemas for auth-service."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, EmailStr, Field


class OrganizationOut(BaseModel):
    id: str
    name: str
    slug: str
    is_active: bool
    subscription_expires_at: datetime
    license_last_checked_at: datetime | None = None

    class Config:
        from_attributes = True


class SubscriptionExtendRequest(BaseModel):
    """Renovacion manual de la suscripcion de una organizacion -- lo que
    usa el operador hoy (a mano, tras confirmar un pago) hasta que el
    servidor central de licencias este conectado a PayPal; ese
    webhook, el dia que exista, va a llamar al mismo endpoint."""

    days: int = Field(default=30, ge=1, le=3650)


class SubscriptionCancelOut(BaseModel):
    """Respuesta del autoservicio "Cancelar suscripcion" -- cancelled
    confirma que la pasarela (PayPal / Mercado Pago) recibio la cancelacion (no se cobra mas),
    pero el acceso sigue activo hasta valid_until (el periodo ya pagado
    no se corta)."""

    cancelled: bool
    valid_until: datetime


class SubscriptionPayLinkRequest(BaseModel):
    """Con que pasarela se quiere pagar. Sin body, PayPal (como antes).
    payer_email es opcional: el email de la cuenta de Mercado Pago del
    pagador, si es distinto del email de su usuario."""

    provider: Literal["paypal", "mercadopago"] = "paypal"
    payer_email: EmailStr | None = Field(default=None, max_length=254)


class BlockedPaymentLinkRequest(BaseModel):
    """Pedido de link de pago desde el login bloqueado (402). pay_token es el que
    el propio 402 entrego: identifica quien acaba de autenticarse y de que
    organizacion es -- la license_key nunca viaja desde el navegador."""

    pay_token: str = Field(min_length=10, max_length=4000)
    provider: Literal["paypal", "mercadopago"]


class PaymentProvidersOut(BaseModel):
    """Pasarelas de pago que ofrece esta instalacion (ver PAYMENT_PROVIDERS)."""

    providers: list[Literal["paypal", "mercadopago"]]


class SubscriptionPayLinkOut(BaseModel):
    """Link de pago (PayPal o Mercado Pago) para pagar por primera vez o
    volver a suscribirse tras cancelar -- ver POST .../subscription/pay-link."""

    payment_url: str


class SubscriptionHistoryOut(BaseModel):
    """Historial de eventos de la licencia (pagos, cancelaciones,
    renovaciones a mano), mas nuevos primero -- ver
    GET .../subscription/history."""

    history: list[str]


class OrganizationCreate(BaseModel):
    """Crea una organizacion nueva Y su primer usuario admin en un solo
    paso -- deliberadamente no hay auto-registro publico de organizaciones
    (a diferencia de /auth/register, que crea un usuario suelto): abrir eso
    significaria que cualquiera puede crear una "empresa" nueva sin
    ninguna verificacion. Solo un platform_admin puede llamar este
    endpoint (ver require_platform_admin en dependencies.py)."""

    name: str = Field(..., min_length=1)
    admin_email: EmailStr
    admin_password: str = Field(min_length=12, max_length=128)
    admin_full_name: str = ""


class SsoConfigIn(BaseModel):
    issuer: str = Field(..., min_length=1, description="Issuer OIDC del proveedor, ej. https://login.microsoftonline.com/<tenant>/v2.0")
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    default_role: str = "analyst"
    enabled: bool = True


class SsoConfigOut(BaseModel):
    """NUNCA incluye client_secret -- una vez guardado, no se vuelve a
    mostrar por API (igual que la api key de un agente de escaneo remoto).
    Si hace falta cambiarlo, se sobreescribe con SsoConfigIn de nuevo."""

    organization_id: str
    issuer: str
    client_id: str
    default_role: str
    enabled: bool

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = ""
    # role_name NO es parte del payload publico a proposito: si lo fuera,
    # cualquiera podria auto-registrarse como admin. El primer usuario que
    # exista en la base se promueve a admin automaticamente (ver el
    # lifespan de main.py); todos los siguientes entran como "analyst" y
    # un admin los puede ascender despues.


class UserOut(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role_name: str
    is_active: bool
    mfa_enabled: bool
    organization_id: str | None = None

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: EmailStr
    # Tope generoso (las contrasenas nuevas llegan a 128): evita pasarle megabytes al hash
    # (bcrypt/passlib levanta PasswordSizeError con >4096 -> 500) y gastar CPU gratis.
    password: str = Field(max_length=1024)
    totp_code: str | None = Field(default=None, max_length=16)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_url: str
    # QR listo para mostrar en <img src=...> (data URI SVG) -- compatible con
    # cualquier app TOTP estandar (RFC 6238).
    qr_code_data_uri: str = ""


class MfaStatusResponse(BaseModel):
    enabled: bool


class MfaVerifyRequest(BaseModel):
    totp_code: str = Field(max_length=16)


class MfaEnrollRequest(BaseModel):
    """Body opcional de POST /auth/mfa/enroll. totp_code solo hace falta para
    RE-enrolar (el usuario YA tiene MFA activo y esta reemplazando el secret,
    ej. perdio el dispositivo) -- ver el chequeo en app/main.py::mfa_enroll.
    En el primer enrolamiento (mfa_enabled todavia False) se ignora."""

    totp_code: str | None = Field(default=None, max_length=16)


class GoogleAuthRequest(BaseModel):
    credential: str = Field(max_length=8192)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=8192)



class UserAdminCreate(BaseModel):
    """Alta de una cuenta hecha por un ADMIN (la unica via donde se elige el rol).
    Con password: cuenta de email+contrasena. Sin password: cuenta que entra con
    Google (pre-aprobada con este rol)."""
    email: EmailStr
    full_name: str = ""
    role: str
    password: str | None = Field(default=None, min_length=12, max_length=128)


class UserAdminUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class UserAdminOut(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role_name: str
    is_active: bool
    mfa_enabled: bool
    auth_provider: str
