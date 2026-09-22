"""Driver de Nmap: descubrimiento de hosts/puertos/servicios y deteccion de
version (-sV) + scripts de deteccion segura (-sC, categoria 'default' y
'safe'). NUNCA se ejecuta con --script vuln en modo exploit ni con scripts
de la categoria 'exploit'/'intrusive'."""
import asyncio
import xml.etree.ElementTree as ET
from app.scanners.base import ScannerDriver, ScanResult

# Flags permitidos explicitamente. Cualquier opcion fuera de esta lista se
# ignora: evita que un `options` arbitrario inyecte flags de explotacion.
_ALLOWED_EXTRA_FLAGS = {"-p", "-Pn", "-6", "--top-ports"}


class NmapDriver(ScannerDriver):
    binary_name = "nmap"

    async def run(self, target: str, options: dict) -> ScanResult:
        cmd = ["nmap", "-sV", "-sC", "--script", "default,safe", "-oX", "-", target]
        ports = options.get("ports")
        if isinstance(ports, str) and ports.replace(",", "").replace("-", "").isdigit():
            cmd[1:1] = ["-p", ports]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="nmap no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            return ScanResult(raw_output="", error="timeout de escaneo (600s)")

        raw = stdout.decode(errors="replace")
        if proc.returncode != 0:
            return ScanResult(raw_output=raw, error=stderr.decode(errors="replace")[:2000])

        return ScanResult(raw_output=raw, findings=_parse_nmap_xml(raw))


def _parse_nmap_xml(xml_text: str) -> list[dict]:
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
