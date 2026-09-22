"""Driver de OpenVAS/GVM: escaneo de vulnerabilidades via Greenbone Vulnerability
Management (protocolo GMP), en modo deteccion (NVTs de deteccion, nunca
scripts de explotacion). Requiere `gvm-cli` y un gvmd accesible; si no estan
disponibles en este contenedor, el driver reporta 'scanner_unavailable' en
lugar de fallar silenciosamente, para que el estado quede visible en el job."""
import asyncio
import os
import xml.etree.ElementTree as ET
from app.scanners.base import ScannerDriver, ScanResult

_SEVERITY_THRESHOLDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def _severity_from_cvss(cvss: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if cvss >= threshold:
            return label
    return "info"


class OpenVasDriver(ScannerDriver):
    binary_name = "gvm-cli"

    async def run(self, target: str, options: dict) -> ScanResult:
        if not self.is_available():
            return ScanResult(
                raw_output="",
                error="gvm-cli/OpenVAS no disponible en este contenedor: requiere un gvmd "
                "accesible via socket o TLS. El job queda marcado como scanner_unavailable.",
            )

        socket_path = options.get("gvm_socket") or os.getenv("GVM_SOCKET_PATH") or "/run/gvmd/gvmd.sock"
        get_targets_cmd = [
            "gvm-cli", "socket", "--socketpath", socket_path,
            "--xml", f"<get_vulns filter='rows=200 host={target}'/>",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *get_targets_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="gvm-cli no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            return ScanResult(raw_output="", error="timeout consultando gvmd (300s)")

        raw = stdout.decode(errors="replace")
        if proc.returncode != 0:
            return ScanResult(
                raw_output=raw,
                error="No se pudo consultar gvmd: " + stderr.decode(errors="replace")[:2000],
            )

        return ScanResult(raw_output=raw, findings=_parse_gmp_vulns(raw))


def _parse_gmp_vulns(xml_text: str) -> list[dict]:
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for vuln in root.findall(".//vuln"):
        name_el = vuln.find("name")
        cvss_el = vuln.find("severity")
        try:
            cvss = float(cvss_el.text) if cvss_el is not None and cvss_el.text else 0.0
        except ValueError:
            cvss = 0.0
        nvt_el = vuln.find("nvt")
        cve_el = nvt_el.find("cve") if nvt_el is not None else None
        findings.append(
            {
                "title": name_el.text if name_el is not None and name_el.text else "hallazgo OpenVAS",
                "description": "",
                "severity": _severity_from_cvss(cvss),
                "cve_id": cve_el.text if cve_el is not None and cve_el.text and cve_el.text != "NOCVE" else None,
            }
        )
    return findings
