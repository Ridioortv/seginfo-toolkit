"""SSO empresarial via OIDC (OpenID Connect) -- login/callback contra el
proveedor que cada organizacion tenga configurado (Azure AD/Entra ID, Okta,
Google Workspace, Auth0, o cualquier proveedor OIDC estandar).

No se implementa SAML en esta version: OIDC cubre practicamente todos los
proveedores empresariales modernos (incluido Azure AD, que es el mas comun
entre los clientes que piden SSO), y el codigo/superficie de ataque es
sensiblemente mas chico que SAML (sin firmas XML, sin XXE, sin metadata
XML) -- ver docs/runbook.md, seccion SSO, para el detalle de esta decision.

Flujo (Authorization Code, sin PKCE -- este es un cliente confidencial de
backend, no una SPA/mobile app que necesite PKCE):

1. GET /auth/oidc/{org_slug}/login
   -> resuelve el discovery document del issuer configurado para esa org,
      genera un `state` (JWT firmado propio, de vida corta, con el org_id y
      un nonce) y redirige (302) al authorization_endpoint del proveedor.
2. El usuario se autentica en el proveedor (fuera de esta app por completo).
3. GET /auth/oidc/{org_slug}/callback?code=...&state=...
   -> valida el `state`, intercambia el `code` por tokens en el
      token_endpoint (con client_id/secret), valida la firma+claims del
      id_token contra el JWKS del proveedor, y si todo cierra emite el JWT
      propio de SentinelOps (issue_tokens) para ese usuario.

Cache de discovery/JWKS: en memoria de proceso, con un TTL corto -- evita
golpear al proveedor en cada login sin arriesgarse a operar meses con una
clave de firma que el proveedor ya rotó.
"""
import time
from urllib.parse import urlencode
import httpx
from jose import jwt as jose_jwt
from jose.exceptions import JWTError as JoseJWTError
from app.models import SsoConfig

_CACHE_TTL_SECONDS = 3600
_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}


class OidcError(Exception):
    """Cualquier fallo del flujo OIDC que deba traducirse a un 401/502 para
    el usuario (issuer inalcanzable, id_token invalido, nonce/state que no
    matchean, etc) -- ver como se atrapa en app/main.py."""


async def _get_json_cached(url: str, cache: dict[str, tuple[float, dict]]) -> dict:
    now = time.monotonic()
    cached = cache.get(url)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise OidcError(f"no se pudo contactar al proveedor de identidad ({url}): {exc}") from exc
    cache[url] = (now, data)
    return data


async def discover(issuer: str) -> dict:
    """Documento de discovery OIDC estandar (RFC: OpenID Connect Discovery
    1.0) -- todos los proveedores serios lo publican en esta ruta fija."""
    return await _get_json_cached(f"{issuer.rstrip('/')}/.well-known/openid-configuration", _discovery_cache)


async def fetch_jwks(jwks_uri: str) -> dict:
    return await _get_json_cached(jwks_uri, _jwks_cache)


async def build_authorize_url(config: SsoConfig, redirect_uri: str, state: str, nonce: str) -> str:
    doc = await discover(config.issuer)
    authorization_endpoint = doc.get("authorization_endpoint")
    if not authorization_endpoint:
        raise OidcError("el discovery document del proveedor no tiene authorization_endpoint")
    params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    return f"{authorization_endpoint}?{urlencode(params)}"


async def exchange_code(config: SsoConfig, code: str, redirect_uri: str) -> dict:
    doc = await discover(config.issuer)
    token_endpoint = doc.get("token_endpoint")
    if not token_endpoint:
        raise OidcError("el discovery document del proveedor no tiene token_endpoint")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError as exc:
        raise OidcError(f"el proveedor de identidad rechazo el intercambio de code por tokens: {exc}") from exc


async def validate_id_token(config: SsoConfig, id_token: str, expected_nonce: str) -> dict:
    """Valida firma (via JWKS del proveedor), issuer, audiencia (== nuestro
    client_id) y nonce (anti-replay) del id_token. Devuelve los claims ya
    verificados (email, name, etc) -- NUNCA se confia en un id_token sin
    pasar por aca."""
    doc = await discover(config.issuer)
    jwks_uri = doc.get("jwks_uri")
    if not jwks_uri:
        raise OidcError("el discovery document del proveedor no tiene jwks_uri")
    jwks = await fetch_jwks(jwks_uri)

    try:
        unverified_header = jose_jwt.get_unverified_header(id_token)
    except JoseJWTError as exc:
        raise OidcError(f"id_token con header invalido: {exc}") from exc

    kid = unverified_header.get("kid")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        raise OidcError("no se encontro la clave publica (kid) del proveedor para verificar el id_token")

    try:
        claims = jose_jwt.decode(
            id_token, key, algorithms=[unverified_header.get("alg", "RS256")],
            audience=config.client_id, issuer=config.issuer,
        )
    except JoseJWTError as exc:
        raise OidcError(f"id_token invalido: {exc}") from exc

    if claims.get("nonce") != expected_nonce:
        raise OidcError("el nonce del id_token no coincide (posible replay o state manipulado)")
    if not claims.get("email"):
        raise OidcError("el proveedor no incluyo un email en el id_token")

    return claims
