"""Driver de YARA: deteccion de patrones/indicadores conocidos en
archivos (webshells, payloads ofuscados, malware generico) usando
reglas PROPIAS de SentinelOps -- ver rules/yara/sentinelops.yar para
el detalle del por que (muchos "rule packs" de YARA de terceros
mezclan licencias distintas regla por regla, varias sin resolver para
uso comercial). Puramente de deteccion: solo lee el archivo/directorio
como bytes, nunca lo ejecuta ni lo modifica.

target: un path (archivo o directorio) que YA existe en el filesystem
de quien ejecuta este driver -- el contenedor de scan-service o la
maquina del agente remoto.

Licencia de YARA: BSD-3-Clause (The YARA Authors) -- invocado como
binario externo via subprocess, igual que trivy/nuclei."""
import asyncio
import os
import re
from app.scanners.base import ScannerDriver, ScanResult

YARA_RULES_FILE = os.getenv("YARA_RULES_FILE", "/opt/sentinelops-yara-rules/sentinelops.yar")

# Con -s, debajo de cada linea "REGLA archivo" YARA imprime una linea de
# detalle por cada cadena que matcheo, formato "0xOFFSET:$id: contenido"
# -- SIN indentacion (a diferencia de lo que un vistazo rapido a la doc
# sugeriria). Un nombre de regla YARA nunca puede empezar con un digito,
# asi que este patron nunca puede confundirse con una linea real
# "REGLA archivo".
_MATCH_LINE_RE = re.compile(r"^(\S+)\s+(.+)$")
_MATCH_DETAIL_RE = re.compile(r"^0x[0-9a-fA-F]+:")

_SEVERITY_BY_RULE = {
    "SentinelOps_EICAR_Test_File": "info",
    "SentinelOps_Embedded_PE_In_NonExecutable": "high",
    "SentinelOps_PHP_Obfuscated_Webshell_Pattern": "critical",
    "SentinelOps_Suspicious_Obfuscated_PowerShell": "high",
    "SentinelOps_Python_Reverse_Shell_Oneliner": "critical",
}


def parse_yara_output(raw: str) -> list[dict]:
    findings: list[dict] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or _MATCH_DETAIL_RE.match(stripped):
            continue
        m = _MATCH_LINE_RE.match(stripped)
        if not m:
            continue
        rule_name, file_path = m.group(1), m.group(2)
        findings.append({
            "title": f"YARA: {rule_name} en {file_path}",
            "description": f"El archivo '{file_path}' coincide con la regla YARA '{rule_name}'.",
            "severity": _SEVERITY_BY_RULE.get(rule_name, "medium"),
            "cve_id": None,
            "service": None,
            "file_path": file_path,
            "rule_id": rule_name,
        })
    return findings


class YaraDriver(ScannerDriver):
    binary_name = "yara"

    async def run(self, target: str, options: dict) -> ScanResult:
        if not os.path.exists(target):
            return ScanResult(
                raw_output="",
                error=f"target '{target}' no existe en el filesystem de quien ejecuta este escaneo",
            )
        cmd = ["yara", "-s"]
        if os.path.isdir(target):
            cmd.append("-r")
        cmd += [YARA_RULES_FILE, target]
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="yara no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ScanResult(raw_output="", error="timeout de escaneo (300s)")
        except asyncio.CancelledError:
            if proc is not None:
                proc.kill()
                await proc.wait()
            raise

        raw = stdout.decode(errors="replace")
        # yara devuelve 0 siempre que corrio bien, haya o no matches (a
        # diferencia de gitleaks/trivy no usa el exit code para avisar
        # hallazgos) -- cualquier otro codigo es un error real.
        if proc.returncode != 0:
            return ScanResult(raw_output=raw, error=stderr.decode(errors="replace")[:2000])
        return ScanResult(raw_output=raw[:200_000], findings=parse_yara_output(raw))
