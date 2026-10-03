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
  - trivy  : CVEs conocidos en imagenes/paquetes/filesystem.
  - nuclei : deteccion por plantillas (se excluyen dos/fuzz/intrusive).
Usa exactamente los mismos comandos/normalizacion que los drivers dentro de
scan-service (ver backend/services/scan-service/app/scanners/*.py). NUNCA
ejecuta scripts de explotacion.

Requisitos
----------
- Python 3.9+ (solo libreria estandar -- no hace falta pip install nada)
- El/los binarios de los escaneres que vayas a usar, en el PATH de esta
  maquina:
    trivy   -> trivy (ver aquasecurity/trivy)
    nuclei  -> nuclei (ver projectdiscovery/nuclei)
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
import ipaddress
import urllib.error
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


SCANNERS = {
    "trivy": run_trivy,
    "nuclei": run_nuclei,
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
    scanner_type = job.get("scanner_type", "nuclei")
    options = job.get("options") or {}
    log(f"job {job_id}: escaneando {target} (scanner={scanner_type})...")

    runner = SCANNERS.get(scanner_type)
    if runner is None:
        submit_result(job_id, "failed", [], error_message=f"este agente no sabe correr el scanner '{scanner_type}'")
        return

    if AGENT_BEHIND_DOCKER_NAT and _is_private_ip_target(target):
        # Sin este chequeo, trivy/nuclei se quedaban varios minutos
        # intentando conectar a una IP de LAN inalcanzable desde adentro de
        # Docker Desktop antes de fallar por timeout -- mejor fallar al toque
        # con un mensaje que diga que hacer.
        error_msg = (
            f"'{target}' parece una IP de LAN, y este agente (Agente Docker) corre DENTRO de Docker "
            f"Desktop: el scanner '{scanner_type}' no tiene forma de atravesar su NAT hacia la red real. "
            "Usa el Agente LAN (remote-agent/agente-lan.ps1, corriendo en una PC con visibilidad real a "
            "esa red) para este target."
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

    _binaries = {"trivy": "trivy", "nuclei": "nuclei"}
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
