"""Dos usuarios 'Ana@x.com' y 'ana@x.com' podian coexistir (el login distinguia mayusculas), y
contrasenas triviales como 'password1234' o '12345678901234' pasaban con solo tener 12+ caracteres."""
import pytest
from pydantic import ValidationError

from app.models import User
from app.schemas import (ChangePasswordRequest, ForgotPasswordRequest, LoginRequest, OrganizationCreate,
                         ResetPasswordRequest, UserAdminCreate, UserCreate)

GOOD = "Sandbox-Pass-12345!"


@pytest.mark.parametrize("make", [
    lambda e: UserCreate(email=e, password=GOOD),
    lambda e: LoginRequest(email=e, password="x"),
    lambda e: ForgotPasswordRequest(email=e),
    lambda e: UserAdminCreate(email=e, role="viewer", password=GOOD),
    lambda e: OrganizationCreate(name="Org", admin_email=e, admin_password=GOOD),
])
def test_emails_are_lowercased_and_trimmed(make):
    obj = make("  Ana.Perez@Empresa.COM ")
    assert getattr(obj, "email", None) or getattr(obj, "admin_email") == "ana.perez@empresa.com"


def test_user_model_lowercases_email_whatever_the_origin():
    assert User(email=" Ana@X.com ").email == "ana@x.com"


@pytest.mark.parametrize("bad", [
    "password1234", "Password1234", "12345678901234", "aaaaaaaaaaaaaa", "qwertyuiop12", "contrasena123",
    "administrator1", "abababababab",
])
def test_trivial_passwords_rejected_everywhere(bad):
    for make in (lambda p: UserCreate(email="a@b.com", password=p),
                 lambda p: UserAdminCreate(email="a@b.com", role="viewer", password=p),
                 lambda p: ResetPasswordRequest(token="t" * 30, new_password=p),
                 lambda p: ChangePasswordRequest(current_password="x", new_password=p),
                 lambda p: OrganizationCreate(name="O", admin_email="a@b.com", admin_password=p)):
        with pytest.raises(ValidationError):
            make(bad)


@pytest.mark.parametrize("good", [GOOD, "correcta caballo bateria grapa", "Mi-perro-se-llama-Tobias-2026", "Xk9#mP2$vL7@qR4!"])
def test_reasonable_passwords_accepted(good):
    assert UserCreate(email="a@b.com", password=good).password == good


def test_admin_create_without_password_still_allowed():
    assert UserAdminCreate(email="a@b.com", role="viewer").password is None


def test_login_does_not_enforce_strength_on_existing_passwords():
    assert LoginRequest(email="a@b.com", password="password1234").password == "password1234"
