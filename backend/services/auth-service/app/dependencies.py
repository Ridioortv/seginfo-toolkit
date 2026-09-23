"""FastAPI dependencies: current user extraction and RBAC guards."""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from backend.shared.security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_claims(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        claims = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalido o expirado")
    if claims.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tipo de token incorrecto")
    return claims


def require_role(*allowed_roles: str):
    """Dependency factory for granular RBAC: require_role('admin', 'soc_manager')."""

    def _checker(claims: dict = Depends(get_current_claims)) -> dict:
        if claims.get("role") not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes")
        return claims

    return _checker


def require_platform_admin(claims: dict = Depends(get_current_claims)) -> dict:
    """Distinto de require_role('admin'): un 'admin' comun administra SU
    propia organizacion (usuarios, SSO de su empresa); esto es para las
    pocas cuentas que administran la plataforma entera (crear
    organizaciones nuevas, verlas todas). Ver User.is_platform_admin en
    models.py para el porque de mantenerlo separado del campo `role`."""
    if not claims.get("platform_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requiere permisos de administrador de plataforma")
    return claims


def require_org_admin_or_platform_admin(org_id: str, claims: dict = Depends(get_current_claims)) -> dict:
    """Para endpoints que administran UNA organizacion especifica (ej. su
    configuracion de SSO): la puede tocar un admin de ESA organizacion, o
    cualquier platform_admin (que administra todas). Un admin de la
    organizacion A nunca puede tocar la configuracion de la organizacion B
    -- ese chequeo de organization_id es lo que evita que un cliente
    modifique el SSO de otro. `org_id` se resuelve automaticamente desde el
    path param del mismo nombre en la ruta que use esta dependency (ver
    /auth/organizations/{org_id}/sso en main.py)."""
    if claims.get("platform_admin"):
        return claims
    if claims.get("role") == "admin" and claims.get("org_id") == org_id:
        return claims
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes para esta organizacion")
