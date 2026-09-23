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
Este agente unicamente sabe correr nmap en modo deteccion (descubrimiento
de puertos/servicios + scripts de deteccion segura, categorias 'default'
y 'safe') -- exactamente el mismo comando que usa el driver de nmap
dentro de scan-service (ver backend/services/scan-service/app/scanners/
nmap.py). NUNCA ejecuta scripts de explotacion ni --script vuln.

Requisitos
----------
- Python 3.9+ (solo libreria estandar -- no hace falta pip install nada)
- nmap instalado y en el PATH del sistema donde corre este script
  (Windows: instalar Nmap for Windows y tildar "Npcap" durante la
  instalacion; Linux/Mac: apt/brew install nmap)

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
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

SCAN_SERVICE_URL = os.environ.get("SCAN_SERVICE_URL", "http://localhost:8003").rstrip("/")
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))

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


def run_nmap(target: str, options: dict) -> tuple[str, list[dict], str]:
    """Corre nmap en modo deteccion contra `target`. Devuelve
    (raw_xml_output, findings, error). Mismo comando exacto que
    app/scanners/nmap.py::NmapDriver.run, para que un escaneo hecho por
    el agente remoto luzca igual (mismos findings normalizados) que uno
    hecho por scan-service adentro del contenedor."""
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


def run_once() -> None:
    jobs = poll_jobs()
    if not jobs:
        return
    for job in jobs:
        job_id = job["id"]
        target = job["target"]
        scanner_type = job.get("scanner_type", "nmap")
        log(f"job {job_id}: escaneando {target} (scanner={scanner_type})...")
        if scanner_type != "nmap":
            submit_result(job_id, "failed", [], error_message=f"este agente solo sabe correr 'nmap', no '{scanner_type}'")
            continue
        raw, findings, error = run_nmap(target, job.get("options") or {})
        if error:
            log(f"job {job_id}: fallo -- {error}")
            submit_result(job_id, "failed", [], raw_output=raw, error_message=error)
        else:
            log(f"job {job_id}: completado, {len(findings)} hallazgo(s)")
            submit_result(job_id, "completed", findings, raw_output=raw)


def main() -> None:
    if not AGENT_API_KEY:
        log("ERROR: falta la variable de entorno AGENT_API_KEY (la api key que te mostro la UI al registrar el agente).")
        sys.exit(1)

    if not check_nmap_available():
        log(
            "ADVERTENCIA: no se encontro 'nmap' en el PATH de esta maquina. "
            "Instalalo antes de seguir (ver remote-agent/README.md) -- el agente "
            "va a seguir corriendo pero todos los jobs van a fallar."
        )

    log("SentinelOps - agente de escaneo remoto iniciado.")
    log(f"  scan-service: {SCAN_SERVICE_URL}")
    log(f"  intervalo de polling: {POLL_INTERVAL_SECONDS}s")
    log("Esperando jobs asignados (Ctrl+C para detener)...")

    while True:
        try:
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
