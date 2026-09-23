"""FastAPI dependencies: current user extraction and RBAC guards."""
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.database import get_db
from backend.shared.security import decode_token
from app import services

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def get_current_claims(token: str | None = Depends(oauth2_scheme)) -> dict:
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    try:
        claims = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalido o expirado")
    if claims.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tipo de token incorrecto")
    return claims


def require_role(*allowed_roles: str):
    def _checker(claims: dict = Depends(get_current_claims)) -> dict:
        if claims.get("role") not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes")
        return claims

    return _checker


async def get_agent_from_key(
    x_agent_key: str | None = Header(default=None, alias="X-Agent-Key"),
    db: AsyncSession = Depends(get_db),
):
    """Autenticacion para el agente de escaneo remoto (ver
    remote-agent/agent.py): un header simple con su api key, nunca un JWT
    -- no hay un usuario/sesion interactiva detras, es un proceso que hace
    polling solo. Se compara contra el hash guardado (ver
    services._hash_agent_key); la key en texto plano nunca se persiste."""
    if not x_agent_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Falta el header X-Agent-Key")
    agent = await services.get_agent_by_key(db, x_agent_key)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Api key de agente invalida")
    return agent
