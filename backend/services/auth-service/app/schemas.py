"""Pydantic request/response schemas for auth-service."""
from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
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

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_url: str


class MfaVerifyRequest(BaseModel):
    totp_code: str

class GoogleAuthRequest(BaseModel):
    credential: str

