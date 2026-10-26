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
import os
import re
import socket

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
# terminar, por el caso "...(x86)", o con "/" por las URLs tipo
# "http://host/"), asi que un target no puede empezar
# con "-" (se interpretaria como flag) ni terminar en un separador
# colgante.
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9/](?:[A-Za-z0-9._:/@\\ ()-]{0,498}[A-Za-z0-9)/])?$")


_URL_USERINFO_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/?#\\\s]*@")


def strip_url_userinfo(text: str) -> str:
    """"https://usuario:token@host/x" -> "https://host/x". Para cualquier lugar
    que MUESTRE o reenvie un target (respuestas de la API, eventos al SIEM):
    el token de un clone nunca debe verse ahi."""
    return _URL_USERINFO_RE.sub(r"\1", text) if isinstance(text, str) else text


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
    if _URL_USERINFO_RE.match(target):
        # Un token pegado en la URL ("https://x-access-token:TOKEN@github.com/...")
        # se guardaba en texto plano y lo devolvia la API a TODOS los roles. Para
        # repos privados usa coderepo-service, que guarda el token cifrado.
        raise ValueError(
            "el target no puede llevar usuario/clave en la URL (user:token@host); "
            "para repositorios privados registralos en Repositorios (el token se guarda cifrado)"
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
# infraestructura INTERNA de TERO Security (los demas contenedores del mismo
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
    # Authority = hasta el primer / ? # o \ (el navegador/curl tratan "\" como "/").
    for sep in ("/", "?", "#", "\\"):
        host = host.split(sep, 1)[0]
    # userinfo ("usuario:clave@host"): el host real es lo que sigue al ULTIMO
    # "@". Sin esto "http://x@postgres:5432/" no matcheaba la lista de
    # servicios internos ni la de metadata (bypass del denylist).
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def _canonical_numeric_ipv4(host: str) -> str:
    """Los clientes HTTP/git/curl aceptan formas numericas de IPv4 que
    ipaddress rechaza: "127.1", "2130706433", "0x7f000001", "0177.0.0.1", "0".
    Se normalizan con inet_aton (igual que el sistema operativo) para que el
    denylist las vea como la IP real."""
    if ":" in host or not host or not re.fullmatch(r"[0-9a-fA-Fx.]+", host):
        return host
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        return host


def reject_dangerous_network_target(target: str) -> None:
    """Levanta ValueError si `target` (ya pasado por validate_target) es un
    target de RED peligroso -- ver el bloque de comentarios de arriba para
    el alcance exacto (nombres de servicio internos + metadata/link-local/
    loopback/multicast/reserved, nunca RFC1918). Quien llama decide cuando
    aplica (ver app/schemas.py): solo a targets de red, nunca a una
    referencia de imagen de trivy ni al target de un agente remoto."""
    has_scheme = bool(_SCHEME_RE.match(target))

    if has_scheme:
        # nuclei/zap solo hablan http(s). "file:///etc/passwd", "gopher://..." o
        # "ftp://..." no son un host de red: _host_only() los dejaba pasar
        # (host vacio o inocuo) hasta el scanner.
        scheme = target.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"el esquema '{scheme}://' no es valido para un escaneo de red: usa http:// o https://")

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
    host = _canonical_numeric_ipv4(host)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname real (no IP, no nombre interno conocido) -- se deja pasar, DNS/el scanner lo resuelve
    if _is_dangerous_ip(ip):
        raise ValueError(
            f"target '{target}' no es un objetivo de escaneo valido (rango reservado/link-local/"
            "loopback -- esto incluye el endpoint de metadata de cloud 169.254.169.254)"
        )


def resolved_target_error(target: str) -> str | None:
    """Chequeo DNS, justo antes de lanzar el escaneo: devuelve un mensaje de
    error si el hostname del target RESUELVE a una IP peligrosa (loopback,
    link-local/metadata, 0.0.0.0, multicast, reservada), o None si esta bien
    (incluye: es una IP literal ya validada, o no resuelve -- ahi el scanner
    falla solo). reject_dangerous_network_target solo mira el TEXTO del target:
    un dominio que el atacante controla ("evil.example") con un registro A a
    169.254.169.254 o a 127.0.0.1 pasaba. RFC1918 sigue permitido (escanear la
    LAN del cliente es el producto).

    Limitacion conocida: el scanner vuelve a resolver el nombre despues
    (DNS rebinding con TTL bajo); cerrarlo del todo exige fijar la IP en el
    scanner, fuera de alcance."""
    host = _host_only(target).rstrip(".")
    if not host:
        return None
    host = _canonical_numeric_ipv4(host)
    try:
        ipaddress.ip_address(host)
        return None  # IP literal: ya la valido reject_dangerous_network_target
    except ValueError:
        pass
    if "/" in host:  # CIDR u otra cosa que no es un nombre
        return None
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    for info in infos:
        raw = info[4][0].split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        if _is_dangerous_ip(ip):
            return (
                f"el nombre '{host}' resuelve a {ip}, una direccion reservada/loopback/link-local "
                "(incluye el endpoint de metadata de cloud); no es un objetivo de escaneo valido"
            )
    return None


def is_private_lan_target(target: str) -> bool:
    """True si `target` (host, URL, IP o CIDR) apunta a una IP privada de LAN
    (RFC1918/ULA). Solo IPs literales: un hostname no se resuelve aca."""
    if not _SCHEME_RE.match(target):
        try:
            return bool(ipaddress.ip_network(target, strict=False).is_private)
        except ValueError:
            pass
    host = _canonical_numeric_ipv4(_host_only(target))
    try:
        return bool(ipaddress.ip_address(host).is_private)
    except ValueError:
        return False


def reject_lan_target_without_agent(target: str) -> None:
    """Un escaneo SIN agente corre dentro de scan-service, en la red de Docker: no
    llega a la LAN real del cliente (Docker Desktop la aisla detras de NAT), asi que
    escanear alli una IP 192.168.x / 10.x / 172.16-31.x da resultados vacios o
    enganosos. Se rechaza con un mensaje claro: para la LAN hay que usar un Agente
    LAN. SCAN_ALLOW_LAN_WITHOUT_AGENT=true lo permite (laboratorio, o Linux donde
    los contenedores si alcanzan la red)."""
    if os.getenv("SCAN_ALLOW_LAN_WITHOUT_AGENT", "").strip().lower() in ("1", "true", "yes", "si"):
        return
    if is_private_lan_target(target):
        raise ValueError(
            f"'{target}' es una direccion de red local (LAN) y un escaneo sin agente no llega a la "
            "red real: usa un Agente LAN (remote-agent) para escanearla. Para objetivos de internet "
            "no hace falta agente."
        )
