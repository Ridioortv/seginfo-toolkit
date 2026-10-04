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
  - trivy    : CVEs conocidos en imagenes/paquetes/filesystem.
  - nuclei   : deteccion por plantillas (se excluyen dos/fuzz/intrusive).
  - zap      : DAST pasivo (spider + analisis pasivo) contra una URL --
               NUNCA escaneo activo/de ataque.
  - semgrep  : SAST con reglas PROPIAS de SentinelOps unicamente (ver
               SEMGREP_RULES_DIR mas abajo) -- jamas 'auto'/'p/...'.
  - gitleaks : secretos/credenciales en el historial de git de un repo.
  - yara     : patrones/indicadores conocidos en un archivo/directorio,
               con reglas PROPIAS de SentinelOps (ver YARA_RULES_FILE).
  - zeek     : captura/analisis pasivo de red durante una ventana de
               tiempo FIJA (options.duration_minutes) -- requiere
               permisos de captura de paquetes en esta maquina.
  - falco    : monitoreo de eventos de runtime durante una ventana de
               tiempo FIJA -- requiere acceso a eBPF/kernel en esta
               maquina.
Usa exactamente los mismos comandos/normalizacion que los drivers dentro de
scan-service (ver backend/services/scan-service/app/scanners/*.py). NUNCA
ejecuta scripts de explotacion ni escaneo activo.

Requisitos
----------
- Python 3.9+ (solo libreria estandar -- no hace falta pip install nada)
- El/los binarios de los escaneres que vayas a usar, en el PATH de esta
  maquina:
    trivy    -> trivy (ver aquasecurity/trivy)
    nuclei   -> nuclei (ver projectdiscovery/nuclei)
    zap      -> zap.sh (ver zaproxy/zaproxy, necesita un JRE instalado)
    semgrep  -> semgrep (ver pip install semgrep)
    gitleaks -> gitleaks (ver gitleaks/gitleaks)
    yara     -> yara (ver VirusTotal/yara)
    zeek     -> zeek (ver zeek/zeek -- Linux unicamente en la practica)
    falco    -> falco (ver falcosecurity/falco -- Linux + eBPF/kernel)
  Para semgrep/yara, ademas, las reglas PROPIAS de SentinelOps tienen que
  estar copiadas en esta maquina (ver SEMGREP_RULES_DIR/YARA_RULES_FILE
  mas abajo -- por defecto, ./rules/semgrep y ./rules/yara relativos a
  donde corre este script; los originales viven en
  backend/services/scan-service/rules/).
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
import re
import subprocess
import sys
import tempfile
import time
import shutil
import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SCAN_SERVICE_URL = os.environ.get("SCAN_SERVICE_URL", "http://localhost:8003").rstrip("/")
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))
# Cuantos jobs puede correr este agente EN PARALELO (ver _process_job/
# run_once mas abajo) -- sin esto, un solo job lento (nuclei contra un
# target que no responde) bloqueaba a todos los demas jobs ya asignados
# en la misma corrida, aunque fueran rapidos. No hace falta que sea muy
# alto: max_jobs de poll_agent_jobs en el backend ya limita a 5 jobs por
# poll.
_MAX_CONCURRENT_JOBS = int(os.environ.get("AGENT_MAX_CONCURRENT_JOBS", "8"))
# Este agente corre DENTRO de un contenedor Docker (ver el servicio
# remote-agent en docker-compose.yml) y por lo tanto detras del NAT de
# Docker Desktop: trivy/nuclei corren tal cual el binario real, que para
# un target de LAN (192.168.x.x, 10.x.x.x, etc.) puede quedarse
# intentando conectar varios minutos antes de fallar, en vez de fallar al
# toque con un mensaje claro. El Agente LAN (agente-lan.ps1, que corre
# FUERA de Docker en el host) no tiene este problema -- ve la LAN real
# directo -- asi que se deja sin marcar (variable ausente/"0").
AGENT_BEHIND_DOCKER_NAT = os.environ.get("AGENT_BEHIND_DOCKER_NAT", "0") == "1"


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
# Sumados por directiva de expansion comercial (Manu, 2026) -- unicamente
# herramientas cuya licencia permite venderlas como parte de este
# producto (ver el documento "Directivas de Expansion Comercial y
# Licencias" y el docstring de cada driver equivalente en
# backend/services/scan-service/app/scanners/ para el detalle exacto de
# licencia/alcance). Misma logica de parseo/severidad que esos drivers,
# duplicada aca a proposito (este agente no importa nada de app/* --
# corre como script Python suelto, sin instalar el backend).
# ==========================================================================

def _is_clonable_url(target: str) -> bool:
    return target.strip().lower().startswith(("http://", "https://"))


_CREDENTIALS_IN_URL_RE = re.compile(r"://[^\s@/]+@")


def _redact_url(text: str) -> str:
    return _CREDENTIALS_IN_URL_RE.sub("://***@", text or "")


def _resolve_code_target(target: str, timeout: int = 180):
    """Para semgrep/gitleaks: devuelve (path, tmpdir_a_borrar_o_None,
    error). Si target es una URL git clonable (http/https), la clona a
    un directorio temporal (que el llamador debe borrar con
    shutil.rmtree despues de usarlo); si es un path local que ya existe
    en ESTA maquina, se devuelve directo, sin crear ni borrar nada."""
    target = (target or "").strip()
    if _is_clonable_url(target):
        tmpdir = tempfile.mkdtemp(prefix="sentinelops-clone-")
        cmd = ["git", "clone", "--single-branch", target, tmpdir]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except FileNotFoundError:
            return None, tmpdir, "git no esta instalado o no esta en el PATH de esta maquina"
        except subprocess.TimeoutExpired:
            return None, tmpdir, f"timeout clonando el repositorio ({timeout}s)"
        if proc.returncode != 0:
            return None, tmpdir, _redact_url(proc.stderr.decode(errors="replace"))[:2000]
        return tmpdir, tmpdir, None
    if os.path.isdir(target) or os.path.isfile(target):
        return target, None, None
    return None, None, (
        f"target '{target}' no es una URL git clonable (http/https) ni un path existente en esta maquina"
    )


def _resolve_duration_seconds(options: dict) -> int:
    """Mismo criterio que app/scanners/_duration.py (zeek/falco: jobs de
    duracion fija, 1-60 minutos, default 5)."""
    raw = options.get("duration_minutes", 5) if isinstance(options, dict) else 5
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        minutes = 5
    return max(1, min(60, minutes)) * 60


# --- Gitleaks (secretos en historial de git, MIT) ------------------------
_GITLEAKS_SEVERITY_BY_MARKER = (
    (("private-key", "aws", "gcp", "azure", "service-account"), "critical"),
    (("token", "api-key", "apikey", "secret", "password", "generic"), "high"),
)


def _classify_gitleaks_severity(rule_id: str) -> str:
    rule = (rule_id or "").lower()
    for markers, severity in _GITLEAKS_SEVERITY_BY_MARKER:
        if any(m in rule for m in markers):
            return severity
    return "medium"


def _redact_secret_match(raw: str) -> str:
    raw = raw or ""
    if len(raw) <= 6:
        return "\u2022\u2022\u2022\u2022"
    padding = min(len(raw) - 5, 20)
    return f"{raw[:3]}{chr(0x2022) * padding}{raw[-2:]}"


def run_gitleaks(target: str, options: dict) -> tuple[str, list[dict], str]:
    path, tmpdir, error = _resolve_code_target(target)
    if error:
        return "", [], error
    try:
        report_fd, report_path = tempfile.mkstemp(prefix="gitleaks-report-", suffix=".json")
        os.close(report_fd)
        try:
            no_git = not os.path.isdir(os.path.join(path, ".git"))
            cmd = [
                "gitleaks", "detect", "--source", path, "--report-format", "json",
                "--report-path", report_path, "--exit-code", "0", "--no-banner",
            ]
            if no_git:
                cmd.append("--no-git")
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=300)
            except FileNotFoundError:
                return "", [], "gitleaks no esta instalado o no esta en el PATH de esta maquina"
            except subprocess.TimeoutExpired:
                return "", [], "timeout de escaneo (300s)"
            if proc.returncode != 0:
                return "", [], proc.stderr.decode(errors="replace")[:2000]
            try:
                with open(report_path, "r", encoding="utf-8") as fh:
                    raw_json = fh.read()
            except OSError:
                raw_json = "[]"
            try:
                data = json.loads(raw_json) if raw_json.strip() else []
            except (json.JSONDecodeError, TypeError, ValueError):
                data = []
            findings = []
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    rule_id = item.get("RuleID", "")
                    file_path = item.get("File", "")
                    findings.append({
                        "title": f"Secreto detectado ({rule_id or 'regla desconocida'}) en {file_path}",
                        "description": item.get("Description", ""),
                        "severity": _classify_gitleaks_severity(rule_id),
                        "cve_id": None,
                        "service": None,
                    })
            return raw_json, findings, ""
        finally:
            try:
                os.remove(report_path)
            except OSError:
                pass
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# --- Semgrep (SAST, motor LGPL-2.1, SOLO reglas propias) -----------------
# --config SIEMPRE una ruta local propia -- NUNCA 'auto' ni 'p/...' (ver
# backend/services/scan-service/rules/semgrep/sentinelops-rules.yml). En
# esta maquina (del agente, no del contenedor) las reglas propias tienen
# que estar copiadas a mano -- ver remote-agent/README.md -- en la ruta
# que indique SENTINELOPS_SEMGREP_RULES_DIR.
# Default: relativo a ESTE archivo (remote-agent/agent.py vive en la raiz
# del repo clonado, con backend/ al lado) -- asi corre sin configuracion
# extra tanto suelto en la maquina de un operador (clone completo del
# repo) como dentro del contenedor "Agente Docker" (que ademas sobreescribe
# esto con SENTINELOPS_SEMGREP_RULES_DIR=/opt/sentinelops-semgrep-rules,
# ver docker-compose.yml, porque ahi agent.py corre SOLO -- sin el resto
# del repo al lado, solo el propio archivo montado).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMGREP_RULES_DIR = os.environ.get(
    "SENTINELOPS_SEMGREP_RULES_DIR",
    os.path.join(_REPO_ROOT, "backend", "services", "scan-service", "rules", "semgrep"),
)
_SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def run_semgrep(target: str, options: dict) -> tuple[str, list[dict], str]:
    path, tmpdir, error = _resolve_code_target(target, timeout=180)
    if error:
        return "", [], error
    try:
        cmd = ["semgrep", "scan", "--config", SEMGREP_RULES_DIR, "--json", "--quiet", "--metrics=off", "--timeout", "60", path]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=420)
        except FileNotFoundError:
            return "", [], "semgrep no esta instalado o no esta en el PATH de esta maquina"
        except subprocess.TimeoutExpired:
            return "", [], "timeout de escaneo (420s)"
        raw = proc.stdout.decode(errors="replace")
        if proc.returncode not in (0, 1):
            return raw, [], proc.stderr.decode(errors="replace")[:2000]
        try:
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            data = {}
        findings = []
        for result in data.get("results", []) or []:
            extra = result.get("extra", {}) or {}
            start = result.get("start", {}) or {}
            findings.append({
                "title": f"{result.get('check_id', 'regla semgrep desconocida')} en {result.get('path', '')}",
                "description": (extra.get("message") or "")[:1000],
                "severity": _SEMGREP_SEVERITY_MAP.get(extra.get("severity", "INFO"), "info"),
                "cve_id": None,
                "service": None,
            })
        return raw, findings, ""
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# --- YARA (patrones/indicadores conocidos en archivos, BSD-3-Clause) -----
YARA_RULES_FILE = os.environ.get(
    "SENTINELOPS_YARA_RULES_FILE",
    os.path.join(_REPO_ROOT, "backend", "services", "scan-service", "rules", "yara", "sentinelops.yar"),
)
_YARA_SEVERITY_BY_RULE = {
    "SentinelOps_EICAR_Test_File": "info",
    "SentinelOps_Embedded_PE_In_NonExecutable": "high",
    "SentinelOps_PHP_Obfuscated_Webshell_Pattern": "critical",
    "SentinelOps_Suspicious_Obfuscated_PowerShell": "high",
    "SentinelOps_Python_Reverse_Shell_Oneliner": "critical",
}
_YARA_MATCH_LINE_RE = re.compile(r"^(\S+)\s+(.+)$")
# "0xOFFSET:$id: contenido" -- linea de detalle de -s, SIN indentar en esta version de yara (bug real: se asumia indentada). Un nombre de regla YARA nunca empieza con un digito, asi que este patron nunca se confunde con una linea real "REGLA archivo".
_YARA_MATCH_DETAIL_RE = re.compile(r"^0x[0-9a-fA-F]+:")


def run_yara(target: str, options: dict) -> tuple[str, list[dict], str]:
    if not os.path.exists(target):
        return "", [], f"target '{target}' no existe en esta maquina"
    cmd = ["yara", "-s"]
    if os.path.isdir(target):
        cmd.append("-r")
    cmd += [YARA_RULES_FILE, target]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=300)
    except FileNotFoundError:
        return "", [], "yara no esta instalado o no esta en el PATH de esta maquina"
    except subprocess.TimeoutExpired:
        return "", [], "timeout de escaneo (300s)"
    raw = proc.stdout.decode(errors="replace")
    if proc.returncode != 0:
        return raw, [], proc.stderr.decode(errors="replace")[:2000]
    findings = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or _YARA_MATCH_DETAIL_RE.match(stripped):
            continue
        m = _YARA_MATCH_LINE_RE.match(stripped)
        if not m:
            continue
        rule_name, file_path = m.group(1), m.group(2)
        findings.append({
            "title": f"YARA: {rule_name} en {file_path}",
            "description": f"El archivo '{file_path}' coincide con la regla YARA '{rule_name}'.",
            "severity": _YARA_SEVERITY_BY_RULE.get(rule_name, "medium"),
            "cve_id": None,
            "service": None,
        })
    return raw, findings, ""


# --- OWASP ZAP (DAST pasivo, Apache 2.0) ---------------------------------
# -quickurl/-quickout: Quick Start de linea de comandos de ZAP, spider +
# analisis PASIVO unicamente -- NUNCA se agrega -quickattack (escaneo
# activo real), misma postura de "solo deteccion" que el resto de la
# plataforma.
_ZAP_RISK_SEVERITY_MAP = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
ZAP_HOME_DIR = os.environ.get("SENTINELOPS_ZAP_HOME_DIR", os.path.expanduser("~/.ZAP"))


def run_zap(target: str, options: dict) -> tuple[str, list[dict], str]:
    if not (target.startswith("http://") or target.startswith("https://")):
        return "", [], "target invalido para ZAP: debe ser una URL http:// o https://"
    tmpdir = tempfile.mkdtemp(prefix="zap-report-")
    report_path = os.path.join(tmpdir, "zap-report.json")
    try:
        cmd = ["zap.sh", "-cmd", "-dir", ZAP_HOME_DIR, "-quickurl", target, "-quickout", report_path, "-quickprogress"]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=600)
        except FileNotFoundError:
            return "", [], "ZAP (zap.sh) no esta instalado o no esta en el PATH de esta maquina"
        except subprocess.TimeoutExpired:
            return "", [], "timeout de escaneo (600s)"
        if not os.path.exists(report_path):
            return proc.stdout.decode(errors="replace")[:5000], [], (
                proc.stderr.decode(errors="replace")[:2000] or "ZAP no genero un reporte"
            )
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                raw_json = fh.read()
        except OSError:
            raw_json = "{}"
        try:
            data = json.loads(raw_json) if raw_json.strip() else {}
        except json.JSONDecodeError:
            data = {}
        findings = []
        for site in data.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                riskdesc = (alert.get("riskdesc") or "").strip().lower()
                risk_key = riskdesc.split(" ", 1)[0] if riskdesc else "informational"
                if risk_key not in _ZAP_RISK_SEVERITY_MAP:
                    risk_key = "informational"
                instances = alert.get("instances", []) or []
                uris = sorted({i.get("uri", "") for i in instances if i.get("uri")})
                findings.append({
                    "title": alert.get("name", "hallazgo ZAP"),
                    "description": (alert.get("desc") or "")[:1000],
                    "severity": _ZAP_RISK_SEVERITY_MAP.get(risk_key, "info"),
                    "cve_id": None,
                    "service": ", ".join(uris[:5]) if uris else site.get("@name"),
                })
        return raw_json, findings, ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --- Zeek/Falco: jobs de DURACION FIJA (ver sus docstrings equivalentes
# en backend/services/scan-service/app/scanners/{zeek,falco}.py para la
# decision de producto completa) -- requieren permisos que esta maquina
# (agente LAN/Docker) puede no tener; si fallan al arrancar, el job
# vuelve con un error claro, nunca "no se encontro nada" en silencio.

_ZEEK_NOTE_SEVERITY_BY_KEYWORD = (
    (("Scan::",), "high"),
    (("SSL::", "Weird::"), "medium"),
)


def _classify_zeek_notice(note_type: str) -> str:
    for keywords, severity in _ZEEK_NOTE_SEVERITY_BY_KEYWORD:
        if any(k in (note_type or "") for k in keywords):
            return severity
    return "low"


def run_zeek(target: str, options: dict) -> tuple[str, list[dict], str]:
    interface = target.strip() if target and target.strip().lower() != "auto" else None
    if interface is not None:
        try:
            ipaddress.ip_address(interface)
            interface = None  # una IP no es una interfaz: se autodetecta
        except ValueError:
            pass
    if interface is None:
        try:
            candidates = [d for d in os.listdir("/sys/class/net") if d != "lo"]
            interface = candidates[0] if candidates else None
        except OSError:
            interface = None
    if not interface:
        return "", [], f"no se pudo resolver una interfaz de red valida a partir de target='{target}'"
    duration_seconds = _resolve_duration_seconds(options or {})
    workdir = tempfile.mkdtemp(prefix="zeek-capture-")
    try:
        cmd = ["zeek", "-i", interface, "-C", "LogAscii::use_json=T", "local"]
        try:
            proc = subprocess.run(cmd, cwd=workdir, capture_output=True, timeout=duration_seconds)
            # Termino SOLO antes de agotarse la ventana -- zeek en modo
            # "-i" vive para siempre hasta que lo matan, asi que esto es
            # siempre una falla real (permisos, interfaz invalida, etc.).
            if proc.returncode != 0:
                return proc.stdout.decode(errors="replace")[:5000], [], (
                    "zeek termino antes de completar la ventana de captura (revisa permisos de captura "
                    "de paquetes en esta maquina): " + proc.stderr.decode(errors="replace")[:1800]
                )
        except subprocess.TimeoutExpired as exc:
            # Fin ESPERADO de la ventana fija -- Python ya mato el
            # proceso (subprocess.run con timeout lo hace solo).
            pass
        except FileNotFoundError:
            return "", [], "zeek no esta instalado o no esta en el PATH de esta maquina"

        notice_path = os.path.join(workdir, "notice.log")
        findings = []
        if os.path.exists(notice_path):
            with open(notice_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    note = event.get("note", "notice desconocido")
                    findings.append({
                        "title": f"Zeek notice: {note}",
                        "description": (event.get("msg") or "")[:1000],
                        "severity": _classify_zeek_notice(note),
                        "cve_id": None,
                        "service": event.get("id.resp_h") or event.get("id.orig_h"),
                    })
        raw_output = f"Captura en interfaz '{interface}' durante {duration_seconds // 60} minuto(s)."
        return raw_output, findings, ""
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


_FALCO_PRIORITY_SEVERITY_MAP = {
    "emergency": "critical", "alert": "critical", "critical": "critical",
    "error": "high", "warning": "medium", "notice": "low",
    "informational": "info", "debug": "info",
}


def run_falco(target: str, options: dict) -> tuple[str, list[dict], str]:
    duration_seconds = _resolve_duration_seconds(options or {})
    cmd = ["falco", "-M", str(duration_seconds), "-o", "engine.kind=modern_ebpf", "-o", "json_output=true"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=duration_seconds + 30)
    except FileNotFoundError:
        return "", [], "falco no esta instalado o no esta en el PATH de esta maquina"
    except subprocess.TimeoutExpired:
        return "", [], f"falco no termino solo tras {duration_seconds + 30}s -- se lo mato a la fuerza"
    raw = proc.stdout.decode(errors="replace")
    if proc.returncode != 0 and not raw.strip():
        return "", [], (
            "falco no pudo arrancar (revisa permisos/acceso a eBPF en esta maquina): "
            + proc.stderr.decode(errors="replace")[:1800]
        )
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "rule" not in event:
            continue
        priority = (event.get("priority") or "").lower()
        findings.append({
            "title": f"Falco: {event.get('rule', 'regla desconocida')}",
            "description": (event.get("output") or "")[:1000],
            "severity": _FALCO_PRIORITY_SEVERITY_MAP.get(priority, "medium"),
            "cve_id": None,
            "service": (event.get("output_fields") or {}).get("container.name"),
        })
    return raw, findings, ""


SCANNERS = {
    "trivy": run_trivy,
    "nuclei": run_nuclei,
    "zap": run_zap,
    "semgrep": run_semgrep,
    "gitleaks": run_gitleaks,
    "yara": run_yara,
    "zeek": run_zeek,
    "falco": run_falco,
}


# zeek/falco NO escanean una direccion de red: su "target" es el nombre de una
# interfaz o una etiqueta descriptiva (ver sus docstrings), asi que el
# chequeo de "IP de LAN inalcanzable desde Docker" no aplica -- si el
# usuario pone una IP ahi, zeek la resuelve a la interfaz local (ver
# run_zeek) y falco la ignora.
_TARGETLESS_SCANNERS = {"zeek", "falco"}
_CODE_SCANNERS = {"semgrep", "gitleaks", "yara"}


def _is_ip_literal(target: str) -> bool:
    try:
        ipaddress.ip_address((target or "").strip())
        return True
    except ValueError:
        return False


def _is_private_ip_target(target: str) -> bool:
    """True si `target` es una IP o CIDR de rango privado (LAN/RFC1918 o
    link-local) -- lo unico que nos importa distinguir aca es "esto es una
    direccion de LAN", no clasificar hostnames (un dominio como
    'intranet.miempresa.local' no se puede resolver sin red real, asi que
    se deja pasar sin bloquear: si de verdad es LAN, va a fallar como
    siempre, pero no perdemos targets legitimos por un falso positivo).
    Si `target` viene con esquema (ej. la URL completa que usa ZAP), se le
    pela el host/puerto antes de intentar parsearlo como IP."""
    t = target.strip()
    if "://" in t:
        t = urllib.parse.urlsplit(t).hostname or ""
    else:
        t = t.split("/")[0] if "/" in t else t
        t = t.split(":")[0] if t.count(":") == 1 else t
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
    scanner_type = job.get("scanner_type", "nuclei")
    options = job.get("options") or {}
    log(f"job {job_id}: escaneando {target} (scanner={scanner_type})...")

    runner = SCANNERS.get(scanner_type)
    if runner is None:
        submit_result(job_id, "failed", [], error_message=f"este agente no sabe correr el scanner '{scanner_type}'")
        return

    if scanner_type in _CODE_SCANNERS and _is_ip_literal(target):
        # semgrep/gitleaks/yara analizan CODIGO/ARCHIVOS, no hosts: una IP
        # pelada nunca es un target valido (ni en el Agente LAN), y el
        # mensaje de "IP de LAN / NAT de Docker" de mas abajo confunde.
        error_msg = (
            f"'{target}' es una direccion IP, pero '{scanner_type}' analiza codigo o archivos, no hosts de red. "
            "Usa como target una URL git (https://github.com/usuario/repo.git) o la ruta de una carpeta/archivo "
            "que exista en la maquina donde corre el agente."
        )
        log(f"job {job_id}: rechazado -- {error_msg}")
        submit_result(job_id, "failed", [], error_message=error_msg)
        return

    if scanner_type not in _TARGETLESS_SCANNERS and AGENT_BEHIND_DOCKER_NAT and _is_private_ip_target(target):
        # Sin este chequeo, trivy/nuclei se quedaban varios minutos
        # intentando conectar a una IP de LAN inalcanzable desde adentro de
        # Docker Desktop antes de fallar por timeout -- mejor fallar al toque
        # con un mensaje que diga que hacer.
        error_msg = (
            f"'{target}' parece una IP de LAN, y este agente (Agente Docker) corre DENTRO de Docker "
            f"Desktop: el scanner '{scanner_type}' (como cualquier otro) no tiene forma de atravesar su "
            "NAT hacia la red real. Usa el Agente LAN (remote-agent/agente-lan.ps1, corriendo en una PC "
            "con visibilidad real a esa red) para este target."
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
    # ej. nuclei contra un rango grande). Cada uno reporta su resultado
    # solo, de forma independiente, apenas termina.
    for job in jobs:
        _job_executor.submit(_process_job, job)


def main() -> None:
    if not AGENT_API_KEY:
        log("ERROR: falta la variable de entorno AGENT_API_KEY (la api key que te mostro la UI al registrar el agente).")
        sys.exit(1)

    _binaries = {
        "trivy": "trivy", "nuclei": "nuclei", "zap": "zap.sh", "semgrep": "semgrep",
        "gitleaks": "gitleaks", "yara": "yara", "zeek": "zeek", "falco": "falco",
    }
    presentes = [s for s, b in _binaries.items() if shutil.which(b) is not None]
    faltantes = [s for s, b in _binaries.items() if shutil.which(b) is None]
    log(f"escaneres disponibles en esta maquina: {', '.join(presentes) if presentes else '(ninguno)'}")
    if faltantes:
        log(
            "NOTA: sin binario para: " + ", ".join(faltantes) + " -- esos jobs volveran con un mensaje claro."
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
