"""Bloqueo de SSRF para URLs configuradas por el operador/tenant que este
backend despues llama por su cuenta (webhooks de notification-service,
conectores de contencion/ticketing de integration-service).

Sin esto, un admin de un tenant (o una cuenta de admin comprometida) puede
configurar un canal/conector apuntando a infraestructura interna --
http://169.254.169.254/ (metadata de AWS/GCP/Azure), http://localhost:5432,
un nombre de servicio de docker-compose (postgres, redis, auth-service),
o una IP RFC1918 -- y hacer que ESTE backend (que si tiene red hacia esa
infraestructura) le pegue por el. Esto es SSRF clasico: el atacante no
necesita acceso de red directo a esos destinos, solo necesita que el
backend haga la request en su nombre.

Se valida el host DOS veces a proposito en cada llamador (ver
notification-service/app/services.py::_send_webhook e
integration-service/app/services.py::_call_connector/_call_jira):
- al crear/actualizar el canal/conector (feedback inmediato al admin)
- justo antes de la llamada HTTP real (defensa en profundidad -- cubre
  configs guardadas antes de este fix, y el caso en que el DNS de un
  hostname ya validado cambio desde que se guardo la config)

Limitacion conocida (DNS rebinding): esta funcion resuelve el hostname y
valida esa resolucion, pero la libreria HTTP (httpx) hace su PROPIA
resolucion de DNS por separado al conectar unos milisegundos despues. Un
atacante que controle el DNS de su propio dominio (TTL bajo) podria hacer
que la IP cambie entre esta validacion y la conexion real de httpx,
devolviendo una IP publica aca y una IP interna en la conexion real. Una
mitigacion completa requeriria fijar la conexion HTTP a la IP exacta que
se valido aca (un transport custom) -- fuera de alcance de este fix, que
cubre el caso mucho mas comun (URL con IP literal privada, o hostname que
resuelve a un rango privado via DNS publico normal, p.ej. localhost,
*.internal, o un hostname que un atacante no controla)."""
import ipaddress
import socket
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}

# Rangos que ipaddress.*.is_private NO cubre en todas las versiones de
# Python pero que igual son internos/no-enrutables publicamente y se
# usan en la practica para metadata de cloud o NAT compartido:
# - 100.64.0.0/10: "Shared Address Space" (RFC 6598) -- CGNAT, usado por
#   algunos proveedores cloud para su red interna.
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),
]


class UnsafeUrlError(ValueError):
    """La URL no se puede usar para una request saliente de este backend
    porque apunta (directamente o via DNS) a una direccion interna/privada,
    o no es una URL http(s) valida."""


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # no deberia pasar (viene de socket.getaddrinfo), bloquear por las dudas
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    return any(ip in net for net in _EXTRA_BLOCKED_NETWORKS)


def validate_outbound_url(url: str, *, field_name: str = "url") -> None:
    """Levanta UnsafeUrlError si `url` no es una URL http(s) segura para
    que este backend la llame el mismo (webhook/conector configurado por
    un admin/operador de un tenant). No devuelve nada -- se llama antes
    de la operacion real (guardar config, o hacer la request) y se deja
    que el caller decida como reportar el error (400 al guardar, status
    'failed' en el log de la accion al ejecutar)."""
    if not url or not url.strip():
        raise UnsafeUrlError(f"{field_name} no puede estar vacio")
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"{field_name} debe ser una URL http:// o https://")
    host = parsed.hostname
    if not host:
        raise UnsafeUrlError(f"{field_name} no tiene un host valido")
    if host.lower() in {"localhost", "metadata.google.internal"}:
        raise UnsafeUrlError(f"{field_name} apunta a un host interno bloqueado ({host})")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"no se pudo resolver el host de {field_name} ({host}): {exc}") from exc
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        if _is_blocked_ip(ip_str):
            raise UnsafeUrlError(
                f"{field_name} resuelve a una direccion IP privada/interna ({host} -> {ip_str}) -- "
                "bloqueado para prevenir SSRF hacia infraestructura interna"
            )
