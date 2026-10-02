"""Validacion del `target` de un escaneo antes de que llegue a cualquier
driver (nmap/nuclei/trivy/openvas) o al agente remoto.

Los drivers ya usan `asyncio.create_subprocess_exec` (nunca `shell=True`),
asi que no hay inyeccion de shell clasica -- pero `target` viaja como un
argumento posicional (nmap, trivy) o interpolado en una query GMP/XML
(openvas), y sin validar:

- Un target que empieza con "-" (ej. "--script=exploit" o "-oN /etc/cron.d/x")
  se puede interpretar como una OPCION de nmap/trivy en vez de como el
  objetivo, permitiendo saltarse las flags fijas (`--script default,safe`)
  o escribir un archivo arbitrario dentro del contenedor.
- openvas.py interpola `target` directo en un string XML -- un target con
  comillas o `<`/`>` podria romper ese XML si no se escapara (SI se
  escapa, ver _xml_escape en app/scanners/openvas.py, pero esta validacion
  es una segunda barrera independiente de eso).

Esta validacion se aplica UNA sola vez, en los schemas Pydantic de
entrada (ScanJobCreate/ScanScheduleCreate/AgentScanJobCreate/
GvmTargetCreate), asi que cualquier target que llegue a un driver o al
agente remoto ya paso por aca."""
import ipaddress
import re

# Letras/numeros, '.', ':', '/', '@', '_', '-' -- alcanza para hostnames,
# IPv4/IPv6, CIDR, URLs de nuclei y referencias de imagen de trivy
# (registry/repo:tag o repo@sha256:digest). Tiene que empezar y terminar
# con un caracter alfanumerico, asi que un target no puede empezar con
# "-" (se interpretaria como flag) ni terminar en un separador colgante.
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:/@-]{0,498}[A-Za-z0-9])?$")


def validate_target(target: str) -> str:
    """Chequeo de SINTAXIS unicamente (seguro para los 4 scanner_type,
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
# producto (ver app/scanners/openvas.py::_build_create_target_xml,
# alive_tests="Consider Alive", y los tests de app/gvm_manage.py/
# test_openvas_dashboard_endpoints.py que mandan hosts="10.0.0.0/24" como
# caso valido) -- un escaner de vulnerabilidades que no puede escanear la
# red interna del propio cliente no sirve para nada.
#
# Lo que SI se bloquea aca es que ese mismo target apunte, en cambio, a la
# infraestructura INTERNA de SentinelOps (los demas contenedores del mismo
# docker-compose, ver docker-compose.yml) o al endpoint de metadata de
# cloud/link-local (169.254.0.0/16, donde vive 169.254.169.254 en AWS/GCP/
# Azure) -- nada de eso es nunca un target legitimo de un escaneo, y
# dejarlo pasar le daria a cualquier analyst autenticado una via de SSRF
# contra el propio control plane de la plataforma (en particular
# openvas-orchestrator, que confia por completo en el aislamiento de red
# interna -- ver openvas-orchestrator/main.py -- y gvmd/postgres/redis, que
# no esperan trafico de escaneo).
#
# Aplicado SOLO a targets "de red" -- scan-service en main.py decide cuando
# llamarlo: siempre para nmap/nuclei/openvas y GvmTargetCreate.hosts, NUNCA
# para una referencia de imagen de trivy (ver validate_target arriba) ni
# para AgentScanJobCreate (el agente remoto corre FUERA de la red docker de
# la plataforma -- en la LAN real del cliente, que es justamente lo que
# tiene que poder alcanzar, ver remote-agent/README.md).

# Nombres de servicio del docker-compose.yml de la plataforma (ver seccion
# "services:") -- nunca un target de escaneo de red legitimo, sea cual sea
# el rango de IP al que resuelvan en la red interna de Compose.
_INTERNAL_SERVICE_NAMES = frozenset({
    "postgres", "redis", "opensearch", "auth-service", "asset-service",
    "vulnerability-tests", "notus-data", "scap-data", "cert-bund-data",
    "dfn-cert-data", "data-objects", "report-formats", "gpg-data",
    "gvm-redis", "pg-gvm", "pg-gvm-migrator", "gvmd", "configure-openvas",
    "openvas", "openvasd", "ospd-openvas", "scan-service",
    "openvas-orchestrator", "remote-agent", "gvm-agent", "vuln-service",
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
        # Target "pelado" (nmap/openvas): puede ser un host, una IP o un
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
