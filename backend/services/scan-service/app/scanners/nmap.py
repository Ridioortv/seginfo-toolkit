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
        # -T4 (timing agresivo) y --host-timeout acotan cuanto se puede
        # tardar un host que no responde -- sin esto, escanear un rango
        # /24 entero donde casi nada contesta (tipico si el rango no es
        # realmente accesible desde este contenedor, ver nota mas abajo)
        # podia comerse el timeout entero de 600s por cada host lento en
        # vez de descartarlo rapido y seguir.
        cmd = [
            "nmap", "-T4", "--host-timeout", "30s",
            "-sV", "-sC", "--script", "default,safe", "-oX", "-", target,
        ]
        ports = options.get("ports")
        if isinstance(ports, str) and ports.replace(",", "").replace("-", "").isdigit():
            cmd[1:1] = ["-p", ports]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="nmap no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            # Sin este kill(), el proceso de nmap sigue corriendo en
            # segundo plano dentro del contenedor aunque el job ya haya
            # quedado marcado como fallido -- no rompe nada, pero
            # desperdicia CPU indefinidamente en cada timeout.
            proc.kill()
            await proc.wait()
            return ScanResult(
                raw_output="",
                error=(
                    "timeout de escaneo (180s) -- si el target es un rango de LAN/oficina "
                    "(ej. 192.168.x.x), recorda que este escaneo corre DENTRO del contenedor "
                    "Docker, no en la red real de la PC: Docker Desktop aisla al contenedor "
                    "detras de NAT, asi que no llega a los dispositivos de tu LAN salvo que "
                    "el propio Docker corra con acceso a esa red."
                ),
            )

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
