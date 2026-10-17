"""Autenticacion servicio-a-servicio para los endpoints /internal/*.

Antes varios endpoints internos (siem-service /internal/rule-tags,
threatintel-service /internal/lookup-batch) eran anonimos "porque solo se
llaman dentro de la red de docker-compose". Pero esos puertos se publican en
el host (BIND_ADDR=0.0.0.0 en instalaciones LAN/produccion) y cualquier
proceso local los alcanza, asi que ahora exigen un JWT de servicio: subject
"system:<servicio>", role admin, firmado con el JWT_SECRET_KEY compartido
del stack (el mismo mecanismo que ya usan soar/case/report-service)."""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError as JWTError

from backend.shared.security import create_access_token, decode_token

_oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def service_auth_headers(service_name: str, org_id: str | None = None) -> dict[str, str]:
    """Header Authorization para llamar a un endpoint /internal/* de otro servicio."""
    token = create_access_token(f"system:{service_name}", "admin", org_id=org_id)
    return {"Authorization": f"Bearer {token}"}


def require_service_token(token: str | None = Depends(_oauth2)) -> dict:
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    try:
        claims = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalido o expirado")
    if claims.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tipo de token incorrecto")
    if claims.get("role") != "admin" or not str(claims.get("sub", "")).startswith("system:"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo servicios internos")
    return claims
