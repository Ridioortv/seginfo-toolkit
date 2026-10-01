#!/usr/bin/env python3
"""SentinelOps - agente de escaneo remoto.

Que problema resuelve
----------------------
scan-service corre DENTRO de un contenedor Docker. En Docker Desktop
(Windows/Mac) los contenedores quedan aislados detras de NAT: no ven la
LAN real de la oficina/cliente aunque el propio Docker Desktop este
instalado en una maquina de esa misma LAN. Este agente resuelve eso
corriendo FUERA de Docker -- como un script Python comun en la PC que
tenga visibilidad real a la red que se quiere escanear (puede ser la
misma PC donde corre SentinelOps, o cualquier otra maquina de esa LAN).

Como funciona (modelo de seguridad)
------------------------------------
El agente SIEMPRE inicia la conexion hacia scan-service (polling), nunca
al reves. Por eso no hace falta abrir ningun puerto de entrada en la red
de la oficina/cliente para que esto funcione -- alcanza con que el
agente pueda llegar, saliente, al puerto ya publicado de scan-service
(por defecto 8003, ver docker-compose.yml). No hay ningun "relay" ni
endpoint publico en internet involucrado: el uso tipico es on-prem /
self-hosted, dentro de la misma red del cliente.

El agente se autentica con una api key propia (nunca con el usuario/JWT
de una persona) via el header 'X-Agent-Key'. La key se genera UNA vez,
al registrar el agente desde la UI de SentinelOps (pagina Escaneos ->
"Agentes de escaneo remoto"), y se pega aca en la config -- scan-service
solo guarda su hash, nunca la key en texto plano.

Alcance (solo deteccion, igual que el resto de la plataforma)
---------------------------------------------------------------
Este agente corre los mismos escaneres de SOLO DETECCION que scan-service,
eligiendo cual por job (campo scanner_type):
  - nmap   : descubrimiento de puertos/servicios (scripts 'default'/'safe').
  - trivy  : CVEs conocidos en imagenes/paquetes/filesystem.
  - nuclei : deteccion por plantillas (se excluyen dos/fuzz/intrusive).
  - openvas: escaneo real de vulnerabilidades via GMP -- REQUIERE que esta
             misma maquina tenga el stack GVM (gvmd + ospd-openvas + feed)
             y gvm-cli; si no, el job falla con un mensaje claro.
Usa exactamente los mismos comandos/normalizacion que los drivers dentro de
scan-service (ver backend/services/scan-service/app/scanners/*.py). NUNCA
ejecuta scripts de explotacion.

Requisitos
----------
- Python 3.9+ (solo libreria estandar -- no hace falta pip install nada)
- El/los binarios de los escaneres que vayas a usar, en el PATH de esta
  maquina:
    nmap    -> nmap (Windows: Nmap for Windows + Npcap; Linux/Mac: apt/brew install nmap)
    trivy   -> trivy (ver aquasecurity/trivy)
    nuclei  -> nuclei (ver projectdiscovery/nuclei)
    openvas -> gvm-cli (paquete gvm-tools) + stack GVM corriendo en esta PC
  Al arrancar, el agente informa que escaneres detecto disponibles. Un job
  cuyo scanner no este instalado falla con un mensaje claro, sin colgar el
  resto.

Configuracion (variables de entorno)
--------------------------------------
  SCAN_SERVICE_URL       Default: http://localhost:8003
                         URL del scan-service a donde hacer polling. Si
                         el agente corre en OTRA maquina de la LAN (no
                         en la misma PC que SentinelOps), usar la IP de
                         esa PC en vez de localhost, ej:
                         http://192.168.1.50:8003
  AGENT_API_KEY          Requerido. La api key que te mostro la UI al
                         registrar el agente (se muestra UNA sola vez).
  POLL_INTERVAL_SECONDS  Default: 10. Cada cuanto pregunta si hay jobs
                         nuevos asignados.

Uso
---
  Windows (cmd):
    set SCAN_SERVICE_URL=http://localhost:8003
    set AGENT_API_KEY=la-key-que-te-dio-la-ui
    python agent.py

  Linux/Mac:
    SCAN_SERVICE_URL=http://localhost:8003 AGENT_API_KEY=la-key python3 agent.py

Ver remote-agent/README.md para mas detalle.
"""
import json
import os
import subprocess
import sys
import time
import shutil
import socket
import ipaddress
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.sax.saxutils import escape as _xml_escape

SCAN_SERVICE_URL = os.environ.get("SCAN_SERVICE_URL", "http://localhost:8003").rstrip("/")
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))
# Cuantos jobs puede correr este agente EN PARALELO (ver _process_job/
# run_once mas abajo) -- sin esto, un solo job lento (nuclei/openvas
# contra un target que no responde) bloqueaba a todos los demas jobs ya
# asignados en la misma corrida, aunque fueran rapidos (ej. nmap). No
# hace falta que sea muy alto: max_jobs de poll_agent_jobs en el backend
# ya limita a 5 jobs por poll.
_MAX_CONCURRENT_JOBS = int(os.environ.get("AGENT_MAX_CONCURRENT_JOBS", "8"))
# Este agente corre DENTRO de un contenedor Docker (ver el servicio
# remote-agent en docker-compose.yml) y por lo tanto detras del NAT de
# Docker Desktop: nmap tiene un fallback propio para atravesarlo (ver
# AGENT_FORCE_INTERNAL_NMAP/_run_python_portscan mas abajo), pero
# trivy/nuclei/openvas NO -- corren tal cual el binario real, que para un
# target de LAN (192.168.x.x, 10.x.x.x, etc.) puede quedarse
# intentando conectar varios minutos antes de fallar, en vez de fallar al
# toque con un mensaje claro. El Agente LAN (agente-lan.ps1, que corre
# FUERA de Docker en el host) no tiene este problema -- ve la LAN real
# directo -- asi que se deja sin marcar (variable ausente/"0").
AGENT_BEHIND_DOCKER_NAT = os.environ.get("AGENT_BEHIND_DOCKER_NAT", "0") == "1"

# Mismos flags permitidos que el driver de nmap dentro de scan-service
# (ver app/scanners/nmap.py) -- se mantiene la misma restriccion aca por
# las mismas razones: options arbitrarias no deben poder inyectar flags
# de explotacion.
_ALLOWED_EXTRA_FLAGS = {"-p", "-Pn", "-6", "--top-ports"}

# Timeouts iguales a los del driver in-container, para que el
# comportamiento sea consistente sin importar donde corra el escaneo.
_HOST_TIMEOUT = "30s"
_PROCESS_TIMEOUT_SECONDS = 180


def log(msg: str) -> None:
    print(f"[agent] {msg}", flush=True)


def _api_request(method: str, path: str, payload: dict | None = None) -> dict:
    url = f"{SCAN_SERVICE_URL}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Agent-Key", AGENT_API_KEY)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def poll_jobs() -> list[dict]:
    result = _api_request("POST", "/agents/poll")
    return result.get("jobs", [])


def submit_result(job_id: str, status: str, findings: list[dict], raw_output: str = "", error_message: str = "") -> None:
    _api_request(
        "POST",
        f"/agents/results/{job_id}",
        {"status": status, "findings": findings, "raw_output": raw_output[:200_000], "error_message": error_message[:2000]},
    )


# --------------------------------------------------------------------------
# Escaner TCP interno (Python puro) -- fallback de nmap cuando el binario no
# esta instalado (tipico en el Agente LAN de host). Descubre puertos abiertos
# por connect() con threads. No reemplaza a nmap en profundidad (no hay
# deteccion de version NSE) pero cubre lo esencial: que hay abierto en la LAN,
# SIN requerir instalar nada.
# --------------------------------------------------------------------------
_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "ms-sql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "ms-wbt-server", 5060: "sip", 5432: "postgresql", 5900: "vnc",
    5985: "wsman", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9000: "http-alt", 9200: "opensearch", 27017: "mongodb",
}
_TOP_PORTS = sorted(set(list(_PORT_SERVICE.keys()) + [
    7, 9, 13, 37, 79, 88, 113, 119, 179, 199, 427, 548, 554, 631, 646, 873,
    990, 1025, 1026, 1027, 1080, 1110, 1900, 2000, 2121, 3000, 3128, 3260,
    3690, 4444, 5000, 5222, 5800, 6000, 6001, 7070, 8008, 8081, 8888, 9090,
    9999, 10000, 49152, 49153, 49154,
]))


def _parse_ports_option(options: dict) -> list[int]:
    p = options.get("ports") if isinstance(options, dict) else None
    if isinstance(p, str) and p.strip():
        out = set()
        for part in p.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    a, b = int(a), int(b)
                    if 0 < a <= b <= 65535 and (b - a) <= 2000:
                        out.update(range(a, b + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                v = int(part)
                if 0 < v <= 65535:
                    out.add(v)
        if out:
            return sorted(out)
    return _TOP_PORTS


def _expand_hosts(target: str) -> list[str]:
    t = target.strip()
    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        return [str(h) for h in net.hosts()][:256]
    try:
        return [socket.gethostbyname(t)]
    except OSError:
        return [t]


def _check_port(host: str, port: int, timeout: float = 0.6):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        return None
    return None


def _run_python_portscan(target: str, options: dict) -> tuple[str, list[dict], str]:
    opts = options if isinstance(options, dict) else {}
    ports = _parse_ports_option(opts)
    try:
        hosts = _expand_hosts(target)
    except ValueError as exc:
        return "", [], f"target invalido para el escaner interno: {exc}"
    if not hosts:
        return "", [], "no hay hosts para escanear en ese rango"
    if len(hosts) > 4:
        ports = [p for p in ports if p in _PORT_SERVICE]
    findings: list[dict] = []
    lines = [f"# escaner TCP interno (Python) -- {len(hosts)} host(s) x {len(ports)} puerto(s)"]
    tasks = [(h, p) for h in hosts for p in ports]
    with ThreadPoolExecutor(max_workers=200) as ex:
        futs = {ex.submit(_check_port, h, p): (h, p) for (h, p) in tasks}
        for fut in as_completed(futs):
            h, p = futs[fut]
            if fut.result() == p:
                svc = _PORT_SERVICE.get(p, "")
                findings.append({
                    "title": f"Puerto abierto {p}/tcp ({svc}) en {h}",
                    "description": "detectado por el escaner TCP interno del agente (sin nmap)",
                    "severity": "info", "port": p, "service": svc,
                })
                lines.append(f"{h}:{p} abierto ({svc})")
    findings.sort(key=lambda f: f["title"])
    return "\n".join(lines), findings, ""


def run_nmap(target: str, options: dict) -> tuple[str, list[dict], str]:
    """Corre nmap en modo deteccion contra `target`. Devuelve
    (raw_xml_output, findings, error). Mismo comando exacto que
    app/scanners/nmap.py::NmapDriver.run, para que un escaneo hecho por
    el agente remoto luzca igual (mismos findings normalizados) que uno
    hecho por scan-service adentro del contenedor."""
    if shutil.which("nmap") is None or os.getenv("AGENT_FORCE_INTERNAL_NMAP"):
        # Escaner TCP por connect(): a diferencia del nmap normal (ping/ARP,
        # que el NAT de Docker Desktop bloquea), un connect() TCP SI atraviesa
        # el NAT, asi que el contenedor puede escanear la LAN real. Tambien es
        # el fallback cuando no hay binario nmap (Agente LAN de host sin nmap).
        log("uso el escaner TCP interno (connect) -- atraviesa el NAT de Docker para escanear la LAN")
        return _run_python_portscan(target, options)
    cmd = [
        "nmap", "-T4", "--host-timeout", _HOST_TIMEOUT,
        "-sV", "-sC", "--script", "default,safe", "-oX", "-", target,
    ]
    ports = options.get("ports") if isinstance(options, dict) else None
    if isinstance(ports, str) and ports.replace(",", "").replace("-", "").isdigit():
        cmd[1:1] = ["-p", ports]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=_PROCESS_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return "", [], "nmap no esta instalado o no esta en el PATH de esta maquina"
    except subprocess.TimeoutExpired:
        return "", [], f"timeout de escaneo ({_PROCESS_TIMEOUT_SECONDS}s) contra {target}"

    raw = proc.stdout.decode(errors="replace")
    if proc.returncode != 0:
        return raw, [], proc.stderr.decode(errors="replace")[:2000]

    return raw, _parse_nmap_xml(raw), ""


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Copia deliberada de app/scanners/nmap.py::_parse_nmap_xml -- se
    mantiene el mismo shape de finding exacto ({title, description,
    severity, port, service}) para que vuln-service (que recibe estos
    findings via /vulnerabilities/ingest) los trate igual sin importar
    si vinieron de un scan-service in-container o de este agente."""
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else "desconocido"
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            svc_name = service.get("name", "") if service is not None else ""
            svc_product = service.get("product", "") if service is not None else ""
            svc_version = service.get("version", "") if service is not None else ""
            findings.append(
                {
                    "title": f"Puerto abierto {port.get('portid')}/{port.get('protocol')} ({svc_name}) en {address}",
                    "description": f"{svc_product} {svc_version}".strip(),
                    "severity": "info",
                    "port": int(port.get("portid")),
                    "service": svc_name,
                }
            )
    return findings


def check_nmap_available() -> bool:
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ==========================================================================
# TRIVY -- vulnerabilidades conocidas (CVE) en imagenes/paquetes/filesystem.
# Mismo shape de finding que app/scanners/trivy.py, para que vuln-service los
# trate igual sin importar si vinieron del contenedor o de este agente.
# ==========================================================================
_TRIVY_SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}
_TRIVY_TIMEOUT_SECONDS = 600


def run_trivy(target: str, options: dict) -> tuple[str, list[dict], str]:
    mode = options.get("mode", "image") if isinstance(options, dict) else "image"
    subcommand = "fs" if mode == "fs" else "image"
    cmd = ["trivy", subcommand, "--format", "json", "--quiet", "--timeout", "8m", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=_TRIVY_TIMEOUT_SECONDS)
    except FileNotFoundError:
        return "", [], "trivy no esta instalado o no esta en el PATH de esta maquina"
    except subprocess.TimeoutExpired:
        return "", [], f"timeout de escaneo ({_TRIVY_TIMEOUT_SECONDS}s) contra {target}"
    raw = proc.stdout.decode(errors="replace")
    if proc.returncode not in (0, 1):
        return raw, [], proc.stderr.decode(errors="replace")[:2000]
    return raw, _parse_trivy_json(raw), ""


def _parse_trivy_json(raw_json: str) -> list[dict]:
    findings: list[dict] = []
    try:
        payload = json.loads(raw_json) if raw_json.strip() else {}
    except json.JSONDecodeError:
        return findings
    for result in payload.get("Results", []) or []:
        target_name = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "title": f"{vuln.get('VulnerabilityID', 'CVE-desconocido')} en {vuln.get('PkgName', '')} ({target_name})",
                "description": (vuln.get("Title") or vuln.get("Description") or "")[:1000],
                "severity": _TRIVY_SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info"),
                "cve_id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
            })
    return findings


# ==========================================================================
# NUCLEI -- deteccion basada en plantillas. Se excluyen dos/fuzz/intrusive:
# solo deteccion no invasiva, NUNCA explotacion activa (igual que el driver
# in-container, app/scanners/nuclei.py).
# ==========================================================================
_NUCLEI_EXCLUDED_TAGS = "dos,fuzz,intrusive"
_NUCLEI_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "info"}
_NUCLEI_TIMEOUT_SECONDS = 600
# Igual que el driver in-container (app/scanners/nuclei.py): -duc evita que
# CADA escaneo chequee/baje templates nuevos (eso era lo que hacia que un
# job de nuclei quedara "assigned" muchisimo tiempo sin completar -- el
# chequeo de templates puede tardar minutos, o mas si la conexion de la PC
# del agente es mala). En cambio refrescamos las templates una vez al
# arrancar y despues cada 12hs en segundo plano (ver
# _maybe_refresh_nuclei_templates), igual que refresh_nuclei_templates en
# scan-service.
_NUCLEI_TEMPLATE_REFRESH_INTERVAL_SECONDS = 12 * 3600
_nuclei_last_template_refresh = 0.0


def _maybe_refresh_nuclei_templates() -> None:
    """Refresca las templates de nuclei si nunca se hizo o si paso mas de
    _NUCLEI_TEMPLATE_REFRESH_INTERVAL_SECONDS desde el ultimo intento
    (exitoso o no -- si no hay internet en este momento no tiene sentido
    reintentar en cada tick del loop de polling). Best-effort: nunca tira,
    solo loguea. Sin esto, un agente que corre semanas/meses con -duc
    quedaria escaneando siempre con las templates del dia que se instalo."""
    global _nuclei_last_template_refresh
    if shutil.which("nuclei") is None:
        return
    now = time.monotonic()
    if now - _nuclei_last_template_refresh < _NUCLEI_TEMPLATE_REFRESH_INTERVAL_SECONDS:
        return
    _nuclei_last_template_refresh = now
    try:
        log("refrescando templates de nuclei en segundo plano...")
        proc = subprocess.run(["nuclei", "-update-templates", "-silent"], capture_output=True, timeout=300)
        if proc.returncode == 0:
            log("templates de nuclei actualizadas.")
        else:
            log(f"no se pudieron actualizar las templates de nuclei (codigo {proc.returncode}): {proc.stderr.decode(errors='replace')[:300]}")
    except subprocess.TimeoutExpired:
        log("timeout (300s) actualizando templates de nuclei -- se reintenta en el proximo ciclo de 12hs.")
    except Exception as exc:  # noqa: BLE001 -- nunca debe tumbar al agente
        log(f"error inesperado actualizando templates de nuclei: {exc}")


def run_nuclei(target: str, options: dict) -> tuple[str, list[dict], str]:
    cmd = ["nuclei", "-target", target, "-etags", _NUCLEI_EXCLUDED_TAGS, "-jsonl", "-silent", "-no-interactsh", "-timeout", "10", "-duc"]
    tags = options.get("tags") if isinstance(options, dict) else None
    if isinstance(tags, str) and tags:
        safe_tags = ",".join(t.strip() for t in tags.split(",") if t.strip().isalnum())
        if safe_tags:
            cmd += ["-tags", safe_tags]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=_NUCLEI_TIMEOUT_SECONDS)
    except FileNotFoundError:
        return "", [], "nuclei no esta instalado o no esta en el PATH de esta maquina"
    except subprocess.TimeoutExpired:
        return "", [], f"timeout de escaneo ({_NUCLEI_TIMEOUT_SECONDS}s) contra {target}"
    raw = proc.stdout.decode(errors="replace")
    if proc.returncode not in (0, 1) and not raw.strip():
        return raw, [], proc.stderr.decode(errors="replace")[:2000]
    return raw, _parse_nuclei_jsonl(raw), ""


def _parse_nuclei_jsonl(raw_jsonl: str) -> list[dict]:
    findings: list[dict] = []
    for line in raw_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = event.get("info", {})
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id") or []
        findings.append({
            "title": info.get("name", event.get("template-id", "hallazgo nuclei")),
            "description": (info.get("description") or "")[:1000],
            "severity": _NUCLEI_SEVERITY_MAP.get(info.get("severity", "unknown"), "info"),
            "cve_id": cve_ids[0] if cve_ids else None,
            "service": event.get("matched-at"),
        })
    return findings


# ==========================================================================
# OPENVAS / GVM -- escaneo real de vulnerabilidades via protocolo GMP.
# A diferencia de nmap/trivy/nuclei (binarios sueltos), openvas necesita el
# MOTOR completo de Greenbone (gvmd + ospd-openvas + feed de NVTs) corriendo
# en ESTA maquina y accesible por su socket. Si gvm-cli no esta instalado o
# faltan credenciales, se devuelve un error claro en vez de colgarse.
# Flujo GMP portado de app/scanners/openvas.py (misma logica, sincronica).
# ==========================================================================
_OV_SEVERITY_THRESHOLDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))
_OV_CONFIG_PREFS = ("full and fast",)
_OV_SCANNER_PREFS = ("openvas default", "openvas")
_OV_PORTLIST_PREFS = ("all iana assigned tcp and udp", "all iana assigned tcp", "all tcp")
_OV_TERMINAL_STATUSES = {"Done", "Stopped", "Interrupted"}
_OV_POLL_INTERVAL = 15
_OV_SCAN_TIMEOUT = int(os.environ.get("GVM_SCAN_TIMEOUT_SECONDS", "1500"))


def _ov_severity(cvss: float) -> str:
    for threshold, label in _OV_SEVERITY_THRESHOLDS:
        if cvss >= threshold:
            return label
    return "info"


def _ov_find_id(xml_text: str, item_tag: str, prefs: tuple) -> str | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    items = []
    for item in root.findall(f".//{item_tag}"):
        item_id = item.get("id")
        name_el = item.find("name")
        name = name_el.text if name_el is not None and name_el.text else ""
        if item_id:
            items.append((item_id, name))
    if not items:
        return None
    for pref in prefs:
        for item_id, name in items:
            if pref in name.lower():
                return item_id
    return items[0][0]


def _ov_response_id(xml_text: str) -> str | None:
    try:
        return ET.fromstring(xml_text).get("id") or None
    except ET.ParseError:
        return None


def _ov_status_ok(xml_text: str) -> bool:
    try:
        return (ET.fromstring(xml_text).get("status") or "").startswith("2")
    except ET.ParseError:
        return False


def _ov_task_status(xml_text: str):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    task = root.find(".//task")
    if task is None:
        return None
    status_el = task.find("status")
    progress_el = task.find("progress")
    status = status_el.text if status_el is not None and status_el.text else "Unknown"
    try:
        progress = int(progress_el.text) if progress_el is not None and progress_el.text else 0
    except ValueError:
        progress = 0
    return status, progress


def _ov_parse_results(xml_text: str) -> list[dict]:
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings
    for result in root.findall(".//result"):
        name_el = result.find("name")
        severity_el = result.find("severity")
        host_el = result.find("host")
        port_el = result.find("port")
        desc_el = result.find("description")
        nvt_el = result.find("nvt")
        cve_el = nvt_el.find("cve") if nvt_el is not None else None
        try:
            cvss = float(severity_el.text) if severity_el is not None and severity_el.text else 0.0
        except ValueError:
            cvss = 0.0
        host = host_el.text if host_el is not None and host_el.text else ""
        findings.append({
            "title": name_el.text if name_el is not None and name_el.text else "hallazgo OpenVAS",
            "description": (desc_el.text or "")[:1000] if desc_el is not None else "",
            "severity": _ov_severity(cvss),
            "cve_id": cve_el.text if cve_el is not None and cve_el.text and cve_el.text != "NOCVE" else None,
            "service": f"{host}:{port_el.text}" if port_el is not None and port_el.text else host or None,
        })
    return findings


def _ov_query(socket_path: str, user: str, password: str, xml: str, timeout: int = 60):
    cmd = ["gvm-cli", "--gmp-username", user, "--gmp-password", password, "socket", "--socketpath", socket_path, "--xml", xml]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return -1, "", "gvm-cli no esta instalado en esta maquina"
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout ({timeout}s) hablando con gvmd"
    return proc.returncode, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")


def run_openvas(target: str, options: dict) -> tuple[str, list[dict], str]:
    if shutil.which("gvm-cli") is None:
        return "", [], (
            "openvas no esta disponible en esta maquina: falta 'gvm-cli' (paquete gvm-tools) y el "
            "stack GVM (gvmd + ospd-openvas + feed de NVTs). openvas necesita ese motor corriendo en "
            "la PC del agente -- para escanear una LAN sin GVM, usa nmap o nuclei en el escaneo remoto."
        )
    opts = options if isinstance(options, dict) else {}
    socket_path = opts.get("gvm_socket") or os.environ.get("GVM_SOCKET_PATH") or "/run/gvmd/gvmd.sock"
    user = opts.get("gvm_user") or os.environ.get("GVM_USER") or ""
    password = opts.get("gvm_password") or os.environ.get("GVM_PASSWORD") or ""
    if not user or not password:
        return "", [], "Faltan credenciales GMP: configura GVM_USER y GVM_PASSWORD en el entorno del agente."

    rc, out, err = _ov_query(socket_path, user, password, "<get_configs/>")
    if rc != 0:
        return out, [], f"no se pudo consultar get_configs: {err[:1000]}"
    config_id = _ov_find_id(out, "config", _OV_CONFIG_PREFS)
    rc, out, err = _ov_query(socket_path, user, password, "<get_scanners/>")
    if rc != 0:
        return out, [], f"no se pudo consultar get_scanners: {err[:1000]}"
    scanner_id = _ov_find_id(out, "scanner", _OV_SCANNER_PREFS)
    rc, out, err = _ov_query(socket_path, user, password, "<get_port_lists/>")
    if rc != 0:
        return out, [], f"no se pudo consultar get_port_lists: {err[:1000]}"
    port_list_id = _ov_find_id(out, "port_list", _OV_PORTLIST_PREFS)
    if not (config_id and scanner_id and port_list_id):
        return "", [], (
            f"gvmd no tiene las entidades minimas (config={config_id}, scanner={scanner_id}, "
            f"port_list={port_list_id}). Puede que el feed de NVTs aun no termino de sincronizar."
        )

    task_name = f"sentinelops-{target}-{int(time.time())}"
    # alive_tests="Consider Alive" por default -- salta la fase de
    # deteccion de host-vivo de gvmd/ospd-openvas (ICMP/ARP Ping, sockets
    # raw/broadcast), que no atraviesa el NAT de Docker Desktop cuando
    # este agente corre DENTRO de un contenedor (Agente Docker, ver
    # AGENT_BEHIND_DOCKER_NAT mas arriba) -- mismo criterio que
    # app/scanners/openvas.py::_build_create_target_xml en scan-service.
    # Override opcional (options["gvm_alive_tests"]) para cuando este
    # mismo agent.py corre con visibilidad de red real (ver remote-agent/
    # openvas-agent/), donde el default de gvmd puede convenir mas
    # (salta hosts caidos mas rapido).
    alive_tests = (opts.get("gvm_alive_tests") or "").strip() or "Consider Alive"
    create_target = (
        f"<create_target><name>{_xml_escape(task_name)}</name>"
        f"<hosts>{_xml_escape(target)}</hosts><port_list id='{port_list_id}'/>"
        f"<alive_tests>{_xml_escape(alive_tests)}</alive_tests></create_target>"
    )
    rc, out, err = _ov_query(socket_path, user, password, create_target)
    if rc != 0 or not _ov_status_ok(out):
        return out, [], f"no se pudo crear el target GVM: {err[:1000] or out[:1000]}"
    target_id = _ov_response_id(out)
    if not target_id:
        return out, [], "create_target no devolvio un id de target"

    create_task = (
        f"<create_task><name>{_xml_escape(task_name)}</name>"
        f"<target id='{target_id}'/><config id='{config_id}'/><scanner id='{scanner_id}'/></create_task>"
    )
    rc, out, err = _ov_query(socket_path, user, password, create_task)
    if rc != 0 or not _ov_status_ok(out):
        return out, [], f"no se pudo crear el task GVM: {err[:1000] or out[:1000]}"
    task_id = _ov_response_id(out)
    if not task_id:
        return out, [], "create_task no devolvio un id de task"

    rc, out, err = _ov_query(socket_path, user, password, f"<start_task task_id='{task_id}'/>")
    if rc != 0:
        return out, [], f"no se pudo iniciar el task GVM: {err[:1000]}"

    deadline = time.monotonic() + _OV_SCAN_TIMEOUT
    last_status, last_progress = "Requested", 0
    while time.monotonic() < deadline:
        time.sleep(_OV_POLL_INTERVAL)
        rc, out, err = _ov_query(socket_path, user, password, f"<get_tasks task_id='{task_id}'/>")
        if rc != 0:
            continue
        parsed = _ov_task_status(out)
        if parsed is None:
            continue
        last_status, last_progress = parsed
        if last_status in _OV_TERMINAL_STATUSES:
            break
    else:
        return "", [], (
            f"timeout esperando que termine el escaneo GVM ({_OV_SCAN_TIMEOUT}s, ultimo estado: "
            f"{last_status} {last_progress}%). Subir GVM_SCAN_TIMEOUT_SECONDS si el target es grande."
        )
    if last_status != "Done":
        return "", [], f"el escaneo GVM termino en estado '{last_status}', no 'Done'"

    rc, out, err = _ov_query(socket_path, user, password, f"<get_results task_id='{task_id}' filter='rows=1000'/>", timeout=120)
    if rc != 0:
        return out, [], f"no se pudieron obtener los resultados: {err[:1000]}"
    return out, _ov_parse_results(out), ""


# Dispatch por tipo de scanner. Cada runner devuelve (raw_output, findings, error).
SCANNERS = {
    "nmap": run_nmap,
    "trivy": run_trivy,
    "nuclei": run_nuclei,
    "openvas": run_openvas,
}


def _is_private_ip_target(target: str) -> bool:
    """True si `target` es una IP o CIDR de rango privado (LAN/RFC1918 o
    link-local) -- lo unico que nos importa distinguir aca es "esto es una
    direccion de LAN", no clasificar hostnames (un dominio como
    'intranet.miempresa.local' no se puede resolver sin red real, asi que
    se deja pasar sin bloquear: si de verdad es LAN, va a fallar como
    siempre, pero no perdemos targets legitimos por un falso positivo)."""
    t = target.strip().split("/")[0] if "/" in target.strip() else target.strip()
    try:
        return ipaddress.ip_address(t).is_private
    except ValueError:
        return False


def _process_job(job: dict) -> None:
    """Corre UN job asignado y reporta su resultado. Vive en su propio
    thread (ver run_once) para que un job lento no bloquee a los demas
    jobs que este mismo agente ya se llevo en el mismo poll."""
    job_id = job["id"]
    target = job["target"]
    scanner_type = job.get("scanner_type", "nmap")
    options = job.get("options") or {}
    log(f"job {job_id}: escaneando {target} (scanner={scanner_type})...")

    runner = SCANNERS.get(scanner_type)
    if runner is None:
        submit_result(job_id, "failed", [], error_message=f"este agente no sabe correr el scanner '{scanner_type}'")
        return

    if scanner_type != "nmap" and AGENT_BEHIND_DOCKER_NAT and _is_private_ip_target(target):
        # Sin este chequeo, trivy/nuclei/openvas se quedaban varios
        # minutos intentando conectar a una IP de LAN inalcanzable desde
        # adentro de Docker Desktop antes de fallar por timeout -- mejor
        # fallar al toque con un mensaje que diga que hacer.
        error_msg = (
            f"'{target}' parece una IP de LAN, y este agente (Agente Docker) corre DENTRO de Docker "
            f"Desktop: el scanner '{scanner_type}' no tiene forma de atravesar su NAT hacia la red real "
            "(a diferencia de nmap, que sí la tiene). Usa el Agente LAN (remote-agent/agente-lan.ps1, "
            "corriendo en una PC con visibilidad real a esa red) para este target."
        )
        log(f"job {job_id}: rechazado -- {error_msg}")
        submit_result(job_id, "failed", [], error_message=error_msg)
        return

    try:
        raw, findings, error = runner(target, options)
    except Exception as exc:  # noqa: BLE001 -- un job roto no debe tumbar el thread ni dejar el job "assigned" para siempre
        log(f"job {job_id}: excepcion no manejada -- {exc}")
        submit_result(job_id, "failed", [], error_message=f"error inesperado en el agente: {exc}")
        return

    if error:
        log(f"job {job_id}: fallo -- {error}")
        submit_result(job_id, "failed", [], raw_output=raw, error_message=error)
    else:
        log(f"job {job_id}: completado, {len(findings)} hallazgo(s)")
        submit_result(job_id, "completed", findings, raw_output=raw)


_job_executor = ThreadPoolExecutor(max_workers=_MAX_CONCURRENT_JOBS)


def run_once() -> None:
    jobs = poll_jobs()
    if not jobs:
        return
    # Se despachan todos a threads y se sigue -- no se espera (as_completed)
    # a que terminen: el loop principal (ver main()) tiene que seguir
    # polleando cada POLL_INTERVAL_SECONDS por jobs NUEVOS aunque los de
    # esta tanda sigan corriendo (algunos pueden tardar varios minutos,
    # ej. openvas). Cada uno reporta su resultado solo, de forma
    # independiente, apenas termina.
    for job in jobs:
        _job_executor.submit(_process_job, job)


def main() -> None:
    if not AGENT_API_KEY:
        log("ERROR: falta la variable de entorno AGENT_API_KEY (la api key que te mostro la UI al registrar el agente).")
        sys.exit(1)

    _binaries = {"trivy": "trivy", "nuclei": "nuclei", "openvas": "gvm-cli"}
    _nmap_label = "nmap" if shutil.which("nmap") else "nmap (escaner interno Python, sin binario)"
    presentes = [_nmap_label] + [s for s, b in _binaries.items() if shutil.which(b) is not None]
    faltantes = [s for s, b in _binaries.items() if shutil.which(b) is None]
    log(f"escaneres disponibles en esta maquina: {', '.join(presentes)}")
    if faltantes:
        log(
            "NOTA: sin binario para: " + ", ".join(faltantes) + " -- esos jobs volveran con "
            "un mensaje claro. nmap SIEMPRE funciona (si no esta el binario, usa el escaner interno)."
        )

    log("SentinelOps - agente de escaneo remoto iniciado.")
    log(f"  scan-service: {SCAN_SERVICE_URL}")
    log(f"  intervalo de polling: {POLL_INTERVAL_SECONDS}s")
    log("Esperando jobs asignados (Ctrl+C para detener)...")

    _maybe_refresh_nuclei_templates()

    while True:
        try:
            _maybe_refresh_nuclei_templates()
            run_once()
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                log("ERROR: api key rechazada por scan-service (401). Verifica AGENT_API_KEY.")
            else:
                log(f"ERROR HTTP {exc.code} hablando con scan-service: {exc.read()[:500]}")
        except urllib.error.URLError as exc:
            log(f"ERROR: no se pudo conectar a scan-service ({SCAN_SERVICE_URL}): {exc.reason}")
        except Exception as exc:  # noqa: BLE001 -- el agente nunca debe morir por un job puntual roto
            log(f"ERROR inesperado: {exc}")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Detenido por el usuario.")
