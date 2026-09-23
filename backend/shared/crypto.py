"""Cifrado simetrico para secretos que se guardan en la base de datos
(client_secret de SSO en auth-service, credenciales de conectores en
integration-service). Sin esto, esos valores quedaban en texto plano en
Postgres -- cualquiera con acceso de lectura a la base (un dump, un
backup mal guardado, otro admin del mismo servidor) podia leer las
credenciales de Azure AD/Okta de un cliente, o la api key de su
firewall/EDR/Jira.

Usa Fernet (AES-128-CBC + HMAC-SHA256, autenticado) de la libreria
`cryptography` -- ya viene instalada en todos los servicios como
dependencia de `python-jose[cryptography]` (que ya se usa para JWT), asi
que no hace falta agregar un requirement nuevo.

ENCRYPTION_KEY (env var) es cualquier string secreto -- el launcher
genera uno random por instalacion en el primer arranque (ver
launcher/cmd/iniciar/main.go), igual que hace con JWT_SECRET_KEY y
POSTGRES_PASSWORD, para que cada cliente tenga su propia clave y no
todas las instalaciones compartan la misma. Se deriva con SHA-256 a un
formato valido para Fernet (32 bytes urlsafe-base64) para no exigirle al
operador que la genere en ese formato exacto a mano."""
import base64
import hashlib
import os
from cryptography.fernet import Fernet, InvalidToken

# Solo para 'docker compose up' sin .env todavia generado (no deberia
# pasar nunca en una instalacion real desde el launcher, que siempre
# genera ENCRYPTION_KEY antes de arrancar) -- NUNCA usar este valor en
# produccion.
_DEV_ENCRYPTION_KEY = "dev-encryption-key-change-me"


def _fernet_key_from_secret(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _get_fernet() -> Fernet:
    secret = os.getenv("ENCRYPTION_KEY", _DEV_ENCRYPTION_KEY)
    return Fernet(_fernet_key_from_secret(secret))


def encrypt_secret(plaintext: str | None) -> str | None:
    if not plaintext:
        return plaintext
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str | None) -> str | None:
    """Si `value` no es un token Fernet valido (por ejemplo, un dato
    guardado antes de este cambio, o el placeholder de desarrollo), se
    asume que ya esta en texto plano y se devuelve tal cual -- evita
    romper instalaciones existentes en vez de fallar duro."""
    if not value:
        return value
    try:
        return _get_fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return value
