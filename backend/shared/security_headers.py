"""Headers de seguridad HTTP, comunes a los 11 microservicios.

Antes ningun servicio los mandaba -- no es explotable por si solo, pero
es la clase de hallazgo que cualquier scanner de seguridad (o un
pentester, o un cliente que audite antes de comprar) marca de entrada, y
cuesta muy poco arreglarlo.

Son API JSON puras (nunca sirven HTML), asi que los valores estan
pensados para eso: nunca se van a renderizar dentro de un <iframe> de
otro sitio, nunca necesitan ejecutar JS/CSS/imagenes de terceros, etc.

No incluye Strict-Transport-Security a proposito: el deploy on-prem
tipico de esta plataforma no termina TLS en estos servicios (ver
docker-compose.yml -- todo corre en HTTP plano dentro de la red de
Docker Compose / localhost). Mandar HSTS sobre una conexion HTTP no hace
nada; si un operador pone esto detras de un reverse proxy con TLS, es
ese proxy el que debe agregar HSTS (y ahi si tiene sentido)."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in _HEADERS.items():
            response.headers.setdefault(name, value)
        return response
