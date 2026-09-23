"""Password hashing and JWT helpers shared across services."""
import os
from datetime import datetime, timedelta, timezone
from jose import jwt

# Los dos valores "de fabrica" que trae .env.example -- el launcher
# (launcher/cmd/iniciar/main.go::ensureEnvFile) genera un JWT_SECRET_KEY
# random en el primer arranque de cada instalacion en vez de copiar
# .env.example tal cual, precisamente para que esto nunca pase en una
# instalacion real. Pero si alguien reconstruye el .env a mano, o corre
# una version vieja del launcher que todavia copiaba el ejemplo literal,
# CUALQUIERA que tenga una copia del instalador (todo cliente que pago,
# y quien sea que la filtre) conoce este valor y puede firmar un JWT
# valido para esa instalacion -- incluyendo uno con platform_admin=True.
# Por eso se verifica en el import de este modulo (se ejecuta en el
# arranque de los 11 microservicios) y no solo en un lugar.
_KNOWN_PLACEHOLDER_SECRETS = {"dev-secret-change-me", "changeme-generate-a-long-random-secret"}

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

if ENVIRONMENT != "development" and JWT_SECRET_KEY in _KNOWN_PLACEHOLDER_SECRETS:
    raise RuntimeError(
        "JWT_SECRET_KEY sigue en su valor de ejemplo con ENVIRONMENT != 'development'. "
        "Esto firmaria tokens que cualquiera con una copia de .env.example podria forjar "
        "(incluyendo un token de platform_admin). Genera un secreto random propio para "
        "esta instalacion (el launcher lo hace solo en el primer arranque -- si ves este "
        "error es porque .env se creo o edito a mano) antes de arrancar en este modo."
    )

_pwd_context = None


def _get_pwd_context():
    # Import diferido a proposito: passlib/bcrypt solo lo necesita
    # auth-service (el unico que hashea/verifica contraseñas, ver
    # hash_password/verify_password mas abajo). Este modulo tambien
    # expone decode_token(), que TODOS los demas microservicios importan
    # via su app/dependencies.py para validar el JWT en cada request --
    # si passlib se importara a nivel de modulo (como estaba antes),
    # cualquiera de esos otros 10 servicios se caia con
    # "ModuleNotFoundError: No module named 'passlib'" al arrancar,
    # aunque nunca llamen a hash_password/verify_password, simplemente
    # porque su requirements.txt (con razon) no incluye passlib.
    global _pwd_context
    if _pwd_context is None:
        from passlib.context import CryptContext
        _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return _pwd_context


def hash_password(plain: str) -> str:
    return _get_pwd_context().hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _get_pwd_context().verify(plain, hashed)


def create_token(subject: str, expires_delta: timedelta, extra_claims: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": subject, "iat": now, "exp": now + expires_delta}
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_access_token(subject: str, role: str, org_id: str | None = None, platform_admin: bool = False) -> str:
    # org_id es opcional (default None) a proposito: los JWT de servicio-a-
    # servicio que ya existian (ej. "system:report-scheduler" en
    # report-service) siguen llamando esta funcion con solo (subject, role)
    # y no se rompen. Cuando esta presente, viaja como claim "org_id" y es
    # lo que el resto de los microservicios usan para filtrar sus tablas por
    # tenant (ver <servicio>/app/dependencies.py::get_current_org_id).
    # platform_admin viaja como claim "platform_admin" y solo lo usa
    # auth-service (para permitir crear/listar organizaciones) -- por eso
    # tiene default False, ningun otro llamador necesita tocarlo.
    extra = {"role": role, "type": "access"}
    if org_id is not None:
        extra["org_id"] = org_id
    if platform_admin:
        extra["platform_admin"] = True
    return create_token(subject, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES), extra)


def create_refresh_token(subject: str) -> str:
    return create_token(subject, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), {"type": "refresh"})


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
