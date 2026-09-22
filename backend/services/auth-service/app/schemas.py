"""Pydantic request/response schemas for auth-service."""
from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    full_name: str = ""
    role_name: str = "analyst"


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
