"""Pydantic request/response schemas for auth-service."""
from datetime import datetime
from typing import Literal
import re
from typing import Annotated
from pydantic import AfterValidator, BaseModel, EmailStr, Field


# --- Normalizacion de email y politica de contrasenas ---------------------------------------
# users.email es unico pero sensible a mayusculas: "Ana@x.com" y "ana@x.com" eran dos cuentas
# distintas (y el login con la otra grafia entraba a la segunda). Todo email que llega en un
# pedido se guarda y compara en minusculas.
NormEmail = Annotated[EmailStr, AfterValidator(lambda v: str(v).strip().lower())]

_COMMON_PASSWORD_BASES = frozenset({
    "password", "passw0rd", "contrasena", "contraseña", "qwertyuiop", "qwerty", "asdfghjkl", "abcdefgh",
    "administrator", "admin", "welcome", "letmein", "iloveyou", "changeme", "monkey", "dragon",
    "football", "baseball", "master", "login", "princess", "sunshine", "superman", "trustno",
    "bienvenido", "argentina", "boca", "river", "tero", "teroseguridad", "sentinelops",
})


def check_password_strength(value: str) -> str:
    """Ademas del largo minimo (12): rechaza contrasenas triviales ("password1234", "12345678901234",
    "aaaaaaaaaaaa", "qwertyuiop12"). No exige simbolos raros: se prefiere una frase larga."""
    if value.isdigit():
        raise ValueError("La contrasena no puede ser solo numeros")
    if len(set(value.lower())) < 5:
        raise ValueError("La contrasena es demasiado repetitiva: usa una frase larga o mezcla mas caracteres")
    base = re.sub(r"[^a-z]", "", value.lower())
    if base in _COMMON_PASSWORD_BASES or (
        len(base) <= 14 and any(base.startswith(w) and len(base) - len(w) <= 2 for w in _COMMON_PASSWORD_BASES)
    ):
        raise ValueError("Esa contrasena es demasiado comun: elegi una frase larga que solo vos conozcas")
    return value


StrongPassword = Annotated[str, Field(min_length=12, max_length=128), AfterValidator(check_password_strength)]


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
    admin_email: NormEmail
    admin_password: StrongPassword
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
    email: NormEmail
    password: StrongPassword
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
    email: NormEmail
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
    email: NormEmail
    full_name: str = ""
    role: str
    password: Annotated[str, Field(min_length=12, max_length=128), AfterValidator(check_password_strength)] | None = None


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


class ForgotPasswordRequest(BaseModel):
    email: NormEmail


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=4096)
    new_password: StrongPassword


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: StrongPassword


class MessageOut(BaseModel):
    message: str


class PasswordResetLinkOut(BaseModel):
    reset_url: str
    expires_minutes: int
    email_sent: bool = False


class RegisterResponse(UserOut):
    """Respuesta del auto-registro: la cuenta creada + el QR del MFA para vincularla ahi mismo
    (sin depender de poder iniciar sesion todavia, p. ej. si la suscripcion esta vencida)."""
    mfa_setup: MfaEnrollResponse | None = None
    mfa_setup_token: str | None = None


class RegisterMfaConfirmRequest(BaseModel):
    setup_token: str = Field(min_length=20, max_length=4096)
    totp_code: str = Field(min_length=6, max_length=16)
