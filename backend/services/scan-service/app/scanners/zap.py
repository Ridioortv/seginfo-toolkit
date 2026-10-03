"""Driver de OWASP ZAP: DAST (deteccion dinamica) contra una URL -- 
spider + analisis PASIVO unicamente, via el modo "Quick Start" de
linea de comandos de ZAP (zap.sh -cmd -quickurl ... -quickout ...).
NUNCA se agrega -quickattack ni ningun flag que habilite el escaneo
ACTIVO (el que de verdad envia payloads de ataque contra el target) --
misma postura de "solo deteccion, nunca explotacion" que nuclei (ver
app/scanners/nuclei.py, que excluye las tags dos/fuzz/intrusive por el
mismo motivo). Si en algun momento se evalua agregar escaneo activo,
eso es un cambio de alcance del producto que hay que decidir aparte,
nunca algo que se habilite por default/sin darse cuenta.

target: una URL http(s) completa (ej. "https://app.cliente.com").
Licencia: Apache 2.0 (ZAP Project / Checkmarx) -- invocado como
binario externo via subprocess, igual que trivy/nuclei."""
import asyncio
import json
import os
import shutil
import tempfile
from app.scanners.base import ScannerDriver, ScanResult

# Directorio de configuracion/estado de ZAP -- tiene que ser escribible
# por el usuario no-root del contenedor (ver chown en el Dockerfile).
ZAP_HOME_DIR = os.getenv("ZAP_HOME_DIR", "/home/sentinelops/.ZAP")

_RISK_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def parse_zap_report(raw_json: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(raw_json) if raw_json.strip() else {}
    except json.JSONDecodeError:
        return findings
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            # riskdesc viene como "Risk (Confidence)" (ej. "Low (Medium)") --
            # hay que tomar SOLO la primera palabra (el riesgo real), nunca
            # buscar cualquiera de las 4 palabras en el string entero: la
            # palabra de CONFIDENCE puede ser "Medium"/"High" y pisar al
            # riesgo real si se busca sin esta distincion (ej. "Low (Medium)"
            # contiene la palabra "medium").
            riskdesc = (alert.get("riskdesc") or "").strip().lower()
            risk_key = riskdesc.split(" ", 1)[0] if riskdesc else "informational"
            if risk_key not in _RISK_SEVERITY_MAP:
                risk_key = "informational"
            instances = alert.get("instances", []) or []
            uris = sorted({i.get("uri", "") for i in instances if i.get("uri")})
            cweid = alert.get("cweid")
            findings.append({
                "title": alert.get("name", "hallazgo ZAP"),
                "description": (alert.get("desc") or "")[:1000],
                "severity": _RISK_SEVERITY_MAP.get(risk_key, "info"),
                "cve_id": None,
                "service": ", ".join(uris[:5]) if uris else site.get("@name"),
                "cwe_id": f"CWE-{cweid}" if cweid and str(cweid) != "-1" else None,
            })
    return findings


class ZapDriver(ScannerDriver):
    binary_name = "zap.sh"

    async def run(self, target: str, options: dict) -> ScanResult:
        if not (target.startswith("http://") or target.startswith("https://")):
            return ScanResult(raw_output="", error="target invalido para ZAP: debe ser una URL http:// o https://")

        tmpdir = tempfile.mkdtemp(prefix="zap-report-")
        report_path = os.path.join(tmpdir, "zap-report.json")
        try:
            cmd = [
                "zap.sh", "-cmd",
                "-dir", ZAP_HOME_DIR,
                "-quickurl", target,
                "-quickout", report_path,
                "-quickprogress",
            ]
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            except FileNotFoundError:
                return ScanResult(raw_output="", error="ZAP (zap.sh) no esta instalado en este contenedor")
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ScanResult(raw_output="", error="timeout de escaneo (600s)")
            except asyncio.CancelledError:
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                raise

            if not os.path.exists(report_path):
                return ScanResult(
                    raw_output=stdout.decode(errors="replace")[:5000],
                    error=(stderr.decode(errors="replace")[:2000]
                           or "ZAP no genero un reporte (fallo antes de completar el escaneo)"),
                )
            try:
                with open(report_path, "r", encoding="utf-8") as fh:
                    raw_json = fh.read()
            except OSError:
                raw_json = "{}"
            return ScanResult(raw_output=raw_json[:200_000], findings=parse_zap_report(raw_json))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
