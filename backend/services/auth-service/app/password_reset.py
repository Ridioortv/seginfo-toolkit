"""Restablecer la contrasena ("Olvide mi contrasena").

El link lleva un token firmado (JWT, type=password_reset) que vence en
RESET_TOKEN_MINUTES minutos. Es de UN SOLO USO sin guardar nada en la base: el
token incluye una huella del hash de contrasena vigente (`pwf`); en cuanto la
contrasena cambia, la huella ya no coincide y el mismo link deja de servir.
Nunca se loguea ni se devuelve el token salvo al administrador que lo pide a
proposito (POST .../password-reset-link).

El mail sale por SMTP (SMTP_HOST/PORT/USER/PASSWORD/FROM, los mismos del canal de
notificaciones). Sin SMTP configurado no se envia nada y el administrador puede
generar el link a mano y pasarselo a la persona."""
import hashlib
import hmac
import logging
import os
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from urllib.parse import quote

from jwt import PyJWTError

from backend.shared.security import create_token, decode_token
from backend.shared import egress

logger = logging.getLogger("auth.password_reset")

RESET_TOKEN_MINUTES = 30
TOKEN_TYPE = "password_reset"


def fingerprint(hashed_password: str | None) -> str:
    """Huella corta del hash vigente: cambia cuando cambia la contrasena."""
    return hashlib.sha256((hashed_password or "").encode()).hexdigest()[:24]


def create_reset_token(user) -> str:
    return create_token(
        user.id,
        timedelta(minutes=RESET_TOKEN_MINUTES),
        {"type": TOKEN_TYPE, "pwf": fingerprint(user.hashed_password)},
    )


def read_reset_token(token: str) -> dict | None:
    """Claims del token si es un token de restablecimiento valido y vigente; None si no."""
    try:
        claims = decode_token(token)
    except PyJWTError:
        return None
    if claims.get("type") != TOKEN_TYPE or not claims.get("sub") or not claims.get("pwf"):
        return None
    return claims


def token_matches_user(claims: dict, user) -> bool:
    """True si el token sigue siendo valido para `user` (nadie cambio la contrasena desde que se emitio)."""
    if user is None or not user.is_active or user.hashed_password is None:
        return False
    return hmac.compare_digest(str(claims.get("pwf", "")), fingerprint(user.hashed_password))


def frontend_url() -> str:
    return (os.getenv("FRONTEND_URL") or "http://localhost:5173").rstrip("/")


def reset_url(token: str) -> str:
    return f"{frontend_url()}/restablecer?token={quote(token, safe='')}"


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip())


def send_reset_email(to_addr: str, url: str) -> bool:
    """Manda el mail con el link. False (sin levantar) si no hay SMTP o falla el envio."""
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        logger.warning("restablecer contrasena: SMTP_HOST no configurado, no se envia el mail")
        return False
    msg = EmailMessage()
    msg["Subject"] = "TERO Security: restablecer tu contrasena"
    msg["From"] = os.getenv("SMTP_FROM", "tero-security@localhost")
    msg["To"] = to_addr
    msg.set_content(
        "Pediste restablecer tu contrasena de TERO Security.\n\n"
        f"Abri este link (vale {RESET_TOKEN_MINUTES} minutos y se puede usar una sola vez):\n{url}\n\n"
        "Si no lo pediste vos, ignora este mensaje: tu contrasena sigue igual."
    )
    try:
        egress.guard(host, "smtp", "Mail para restablecer contrasenas")
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as server:
            server.ehlo()
            if os.getenv("SMTP_STARTTLS", "true").lower() != "false":
                try:
                    server.starttls()
                    server.ehlo()
                except smtplib.SMTPNotSupportedError:
                    pass
            if os.getenv("SMTP_USER"):
                server.login(os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", ""))
            server.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 - un fallo de mail nunca debe romper ni revelar nada
        logger.warning("restablecer contrasena: no se pudo enviar el mail", extra={"error": type(exc).__name__})
        return False
