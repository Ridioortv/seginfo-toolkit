"""Driver de Nuclei: deteccion basada en plantillas (CVEs conocidos,
exposiciones, malas configuraciones, huella tecnologica). Se excluyen
explicitamente las categorias 'dos', 'fuzz' e 'intrusive': solo se
ejecutan plantillas de deteccion pasiva/no invasiva. NUNCA se habilitan
plantillas de explotacion activa.

Las plantillas se descargan una vez al construir la imagen (ver Dockerfile:
`nuclei -update-templates`) y se refrescan en segundo plano cada 12hs (ver
app/services.py::refresh_nuclei_templates, registrado en app/main.py). Por
eso cada escaneo corre con -duc (disable update check): sin esto, nuclei
chequeaba/actualizaba plantillas en CADA escaneo individual, que era la
causa principal de que "tardara mucho"."""
import asyncio
import json
import re
import xml.etree.ElementTree as ET
from app.scanners.base import ScannerDriver, ScanResult

_EXCLUDED_TAGS = "dos,fuzz,intrusive"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Mismo problema que nmap.py::_UNREACHABLE_ERROR, adaptado a nuclei: ver
# _preflight_host_up mas abajo para el porque.
_UNREACHABLE_ERROR = (
    "el chequeo de disponibilidad (nmap -sn) no pudo confirmar que el host "
    "este activo -- nuclei no tiene una fase de descubrimiento propia, asi "
    "que un target inalcanzable simplemente no genera coincidencias en "
    "ninguna plantilla y termina en '0 hallazgos', identico a un escaneo "
    "realmente limpio. Si es una IP de tu LAN/oficina (ej. 192.168.x.x), es "
    "el mismo aislamiento de red ya conocido: este escaneo corrio DENTRO "
    "del contenedor Docker sin agente, y Docker Desktop lo aisla detras de "
    "NAT -- usa 'Escaneos remotos' con un agente (o revisa el target si "
    "esperabas un host de internet)."
)


def _build_nuclei_cmd(target: str, options: dict) -> list[str]:
    """Funcion pura (sin I/O) para poder testear la construccion del
    comando sin ejecutar nuclei de verdad."""
    cmd = [
        "nuclei", "-target", target, "-etags", _EXCLUDED_TAGS,
        "-jsonl", "-silent", "-no-interactsh", "-timeout", "10", "-duc",
    ]
    tags = options.get("tags")
    if isinstance(tags, str) and tags:
        safe_tags = ",".join(t.strip() for t in tags.split(",") if t.strip().isalnum())
        if safe_tags:
            cmd += ["-tags", safe_tags]
    return cmd


def _extract_host(target: str) -> str:
    """Extrae el host puro de un target de nuclei -- que puede venir como
    una URL con esquema/puerto/path (ej. 'https://192.168.0.143:8443/api')
    -- para poder pasarselo a `nmap -sn`, que solo entiende
    hosts/IPs/CIDRs, no URLs."""
    host = _SCHEME_RE.sub("", target, count=1)
    host = host.split("/", 1)[0]
    if not host.startswith("["):  # IPv6 entre corchetes: no lo tocamos
        host = host.split(":", 1)[0]
    return host or target


async def _preflight_host_up(host: str) -> bool | None:
    """Chequeo rapido de disponibilidad reusando el descubrimiento de nmap
    (ICMP + fallback ARP/TCP-SYN), NO un escaneo completo -- nuclei no
    tiene una fase de descubrimiento propia: si el target esta caido o es
    inalcanzable, nuclei simplemente no encuentra matches en ninguna
    plantilla y termina con returncode 0, indistinguible de "target limpio,
    sin hallazgos" (ver el mismo problema en nmap.py, resuelto ahi leyendo
    <runstats> del propio escaneo). Devuelve True/False si nmap pudo
    determinarlo, o None si nmap no esta disponible o el chequeo mismo
    fallo -- en ese caso NO bloqueamos el escaneo real de nuclei, se sigue
    igual que antes de este chequeo (mejor un falso negativo ocasional que
    romper escaneos que hoy funcionan)."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sn", "-T4", "--host-timeout", "5s", "-oX", "-", host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
    except (FileNotFoundError, asyncio.TimeoutError):
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        return None
    except asyncio.CancelledError:
        if proc is not None:
            proc.kill()
            await proc.wait()
        raise

    if proc.returncode != 0:
        return None
    try:
        root = ET.fromstring(stdout.decode(errors="replace"))
    except ET.ParseError:
        return None
    runstats = root.find("runstats")
    if runstats is None:
        return None
    hosts_el = runstats.find("hosts")
    if hosts_el is None:
        return None
    try:
        up, total = int(hosts_el.get("up", "0")), int(hosts_el.get("total", "0"))
    except (TypeError, ValueError):
        return None
    if total == 0:
        return None
    return up > 0


class NucleiDriver(ScannerDriver):
    binary_name = "nuclei"

    async def run(self, target: str, options: dict) -> ScanResult:
        # Preflight de disponibilidad -- ver _preflight_host_up. Si nmap no
        # esta disponible o no pudo determinar nada, host_up queda en None
        # y seguimos directo a nuclei igual que antes de este chequeo.
        host_up = await _preflight_host_up(_extract_host(target))
        if host_up is False:
            return ScanResult(raw_output="", error=_UNREACHABLE_ERROR)

        cmd = _build_nuclei_cmd(target, options)

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="nuclei no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ScanResult(raw_output="", error="timeout de escaneo (600s)")
        except asyncio.CancelledError:
            # Ver nmap.py: sin este kill(), nuclei sigue corriendo huerfano
            # dentro del contenedor aunque el job ya haya quedado cancelado.
            if proc is not None:
                proc.kill()
                await proc.wait()
            raise

        raw = stdout.decode(errors="replace")
        if proc.returncode not in (0, 1) and not raw.strip():
            return ScanResult(raw_output=raw, error=stderr.decode(errors="replace")[:2000])

        return ScanResult(raw_output=raw, findings=_parse_nuclei_jsonl(raw))


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
        findings.append(
            {
                "title": info.get("name", event.get("template-id", "hallazgo nuclei")),
                "description": (info.get("description") or "")[:1000],
                "severity": _SEVERITY_MAP.get(info.get("severity", "unknown"), "info"),
                "cve_id": cve_ids[0] if cve_ids else None,
                "service": event.get("matched-at"),
            }
        )
    return findings
