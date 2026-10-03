"""Validacion del `target` de un escaneo antes de que llegue a cualquier
driver (nuclei/trivy) o al agente remoto.

Los drivers ya usan `asyncio.create_subprocess_exec` (nunca `shell=True`),
asi que no hay inyeccion de shell clasica -- pero `target` viaja como un
argumento posicional (nuclei, trivy), y sin validar:

- Un target que empieza con "-" (ej. "-tags=dos" o alguna otra flag) se
  puede interpretar como una OPCION del binario en vez de como el
  objetivo, permitiendo saltarse las flags fijas (`-etags dos,fuzz,intrusive`)
  o alterar el comportamiento del escaneo de forma inesperada.

Esta validacion se aplica UNA sola vez, en los schemas Pydantic de
entrada (ScanJobCreate/ScanScheduleCreate/AgentScanJobCreate), asi que
cualquier target que llegue a un driver o al agente remoto ya paso por
aca."""
import ipaddress
import re

# Letras/numeros, '.', ':', '/', '@', '_', '-' -- alcanza para hostnames,
# IPv4/IPv6, CIDR, URLs de nuclei/zap y referencias de imagen de trivy
# (registry/repo:tag o repo@sha256:digest). Se agrega ademas espacio,
# '\' y '()' -- sin esto, un path local de Windows (ej.
# "C:\Users\manu\mi repo" o "C:\Program Files (x86)\...", target
# valido para semgrep/gitleaks/yara cuando corren en el agente remoto
# nativo -- agente-lan.ps1, ver remote-agent/) queda bloqueado por este
# chequeo de SINTAXIS antes de llegar al driver. Sigue siendo seguro
# ampliarlo: ningun driver usa shell=True (todos corren con
# asyncio.create_subprocess_exec/subprocess.run con una lista de
# argumentos), asi que un espacio o '\' en un argumento nunca habilita
# inyeccion de comandos, solo pasa tal cual como parte de ese argumento.
# Tiene que empezar y terminar con un caracter alfanumerico (o ')' al
# terminar, por el caso "...(x86)"), asi que un target no puede empezar
# con "-" (se interpretaria como flag) ni terminar en un separador
# colgante.
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9/](?:[A-Za-z0-9._:/@\\ ()-]{0,498}[A-Za-z0-9)])?$")


def validate_target(target: str) -> str:
    """Chequeo de SINTAXIS unicamente (seguro para los 2 scanner_type,
    incluido trivy con una referencia de imagen tipo "postgres:16" o
    "redis:7-alpine"). El chequeo de SSRF (reject_dangerous_network_target,
    mas abajo) es un paso SEPARADO a proposito: una referencia de imagen de
    trivy no es un host de red, y aplicarle el mismo denylist de nombres de
    servicio de la plataforma (ver mas abajo) rechazaria por error targets
    de trivy legitimos y muy comunes como "postgres:16" o "redis:7"."""
    target = target.strip()
    if not target:
        raise ValueError("el target no puede estar vacio")
    if not _SAFE_TARGET_RE.match(target):
        raise ValueError(
            "target invalido -- solo se permiten letras, numeros, '.', ':', '/', '@', '_' y '-', "
            "y no puede empezar con '-' (se interpretaria como una opcion de linea de comandos)"
        )
    return target


# --- SSRF: targets que nunca deben llegar a un driver "de red" -------------
#
# A proposito NO se bloquean rangos RFC1918 (10/8, 172.16/12, 192.168/16):
# escanear la LAN/oficina propia del cliente es una funcionalidad real del
# producto -- un escaner de vulnerabilidades que no puede escanear la red
# interna del propio cliente no sirve para nada.
#
# Lo que SI se bloquea aca es que ese mismo target apunte, en cambio, a la
# infraestructura INTERNA de SentinelOps (los demas contenedores del mismo
# docker-compose, ver docker-compose.yml) o al endpoint de metadata de
# cloud/link-local (169.254.0.0/16, donde vive 169.254.169.254 en AWS/GCP/
# Azure) -- nada de eso es nunca un target legitimo de un escaneo, y
# dejarlo pasar le daria a cualquier analyst autenticado una via de SSRF
# contra el propio control plane de la plataforma (postgres/redis/el
# resto de los microservicios, que no esperan trafico de escaneo).
#
# Aplicado SOLO a targets "de red" -- scan-service en main.py decide cuando
# llamarlo: siempre para nuclei, NUNCA para una referencia de imagen de
# trivy (ver validate_target arriba) ni para AgentScanJobCreate (el agente
# remoto corre FUERA de la red docker de la plataforma -- en la LAN real
# del cliente, que es justamente lo que tiene que poder alcanzar, ver
# remote-agent/README.md).

# Nombres de servicio del docker-compose.yml de la plataforma (ver seccion
# "services:") -- nunca un target de escaneo de red legitimo, sea cual sea
# el rango de IP al que resuelvan en la red interna de Compose.
_INTERNAL_SERVICE_NAMES = frozenset({
    "postgres", "redis", "opensearch", "auth-service", "asset-service",
    "scan-service", "remote-agent", "vuln-service",
    "siem-service", "soar-service", "case-service", "purple-service",
    "report-service", "notification-service", "integration-service",
    "threatintel-service", "asm-service", "cloud-service",
    "coderepo-service", "frontend", "localhost",
})

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _is_dangerous_ip(ip) -> bool:
    """Link-local (incluye 169.254.169.254 de metadata), loopback,
    unspecified (0.0.0.0/::) o multicast -- nunca un target real. NO
    incluye is_private: los rangos RFC1918 son un target valido (ver
    docstring de arriba)."""
    return bool(ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved)


def _host_only(value: str) -> str:
    """Pela esquema/path/puerto/corchetes IPv6 de un target que puede venir
    como URL (nuclei) para quedarse solo con el host, para matchear contra
    _INTERNAL_SERVICE_NAMES o parsearlo como IP suelta. A diferencia de
    validate_target (que acepta referencias de imagen tipo "repo:tag"),
    esta funcion solo la llaman targets que YA se sabe son de red (ver
    reject_dangerous_network_target), asi que no hace falta preocuparse
    por un "postgres:16" de trivy aca."""
    host = _SCHEME_RE.sub("", value, count=1)
    host = host.split("/", 1)[0]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def reject_dangerous_network_target(target: str) -> None:
    """Levanta ValueError si `target` (ya pasado por validate_target) es un
    target de RED peligroso -- ver el bloque de comentarios de arriba para
    el alcance exacto (nombres de servicio internos + metadata/link-local/
    loopback/multicast/reserved, nunca RFC1918). Quien llama decide cuando
    aplica (ver app/schemas.py): solo a targets de red, nunca a una
    referencia de imagen de trivy ni al target de un agente remoto."""
    has_scheme = bool(_SCHEME_RE.match(target))

    if not has_scheme:
        # Target "pelado" (nuclei): puede ser un host, una IP o un
        # CIDR ("10.0.0.0/24") -- probarlo como red primero para que una
        # mascara quede cubierta por el chequeo de rango (ej.
        # "169.254.0.0/16" como CIDR explicito).
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = None
        if network is not None:
            if _is_dangerous_ip(network):
                raise ValueError(
                    f"target '{target}' no es un objetivo de escaneo valido (rango reservado/"
                    "link-local/loopback -- esto incluye el endpoint de metadata de cloud "
                    "169.254.169.254)"
                )
            return

    host = _host_only(target)
    if host.rstrip(".").lower() in _INTERNAL_SERVICE_NAMES:
        raise ValueError(
            f"target '{host}' referencia un servicio interno de la plataforma, no un objetivo de escaneo valido"
        )
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname real (no IP, no nombre interno conocido) -- se deja pasar, DNS/el scanner lo resuelve
    if _is_dangerous_ip(ip):
        raise ValueError(
            f"target '{target}' no es un objetivo de escaneo valido (rango reservado/link-local/"
            "loopback -- esto incluye el endpoint de metadata de cloud 169.254.169.254)"
        )
