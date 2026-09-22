"""Driver de Trivy: analisis de vulnerabilidades conocidas (CVE) en imagenes
de contenedor, sistemas de archivos y manifiestos de dependencias. Es
puramente de deteccion: compara paquetes instalados contra bases de datos
de CVEs publicas, nunca ejecuta codigo contra el objetivo."""
import asyncio
import json
from app.scanners.base import ScannerDriver, ScanResult

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


class TrivyDriver(ScannerDriver):
    binary_name = "trivy"

    async def run(self, target: str, options: dict) -> ScanResult:
        mode = options.get("mode", "image")
        subcommand = "fs" if mode == "fs" else "image"
        cmd = ["trivy", subcommand, "--format", "json", "--quiet", "--timeout", "8m", target]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=540)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="trivy no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            return ScanResult(raw_output="", error="timeout de escaneo (540s)")

        raw = stdout.decode(errors="replace")
        if proc.returncode not in (0, 1):
            return ScanResult(raw_output=raw, error=stderr.decode(errors="replace")[:2000])

        return ScanResult(raw_output=raw, findings=_parse_trivy_json(raw))


def _parse_trivy_json(raw_json: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(raw_json) if raw_json.strip() else {}
    except json.JSONDecodeError:
        return findings

    for result in data.get("Results", []) or []:
        target_name = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "title": f"{vuln.get('VulnerabilityID', 'CVE-desconocido')} en {vuln.get('PkgName', '')} ({target_name})",
                    "description": (vuln.get("Title") or vuln.get("Description") or "")[:1000],
                    "severity": _SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info"),
                    "cve_id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                }
            )
    return findings
