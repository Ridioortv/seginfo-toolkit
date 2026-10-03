"""Driver de Semgrep: analisis estatico de codigo (SAST) usando
EXCLUSIVAMENTE reglas PROPIAS de SentinelOps -- ver
rules/semgrep/sentinelops-rules.yml para el detalle completo del por
que. --config SIEMPRE apunta a ese archivo/directorio propio, JAMAS a
`auto` ni a ningun ruleset del registro publico (`p/...`, `r/...`): el
ruleset publico de Semgrep ("semgrep-rules") se distribuye bajo la
"Semgrep Rules License v1.0", que prohibe EXPLICITAMENTE ofrecerlo
"as part of a service to third parties" -- exactamente lo que haria
este producto si lo usara para escanear codigo de un cliente. Esta
restriccion NUNCA debe relajarse sin volver a revisar esa licencia.

target: URL git clonable (https://...) o path local existente (ver
app/scanners/_codetarget.py). Licencia del motor de Semgrep: LGPL 2.1,
invocado como binario externo via subprocess -- mismo patron que
trivy/nuclei (nunca linkeado ni distribuido como libreria)."""
import asyncio
import json
import os
from app.scanners.base import ScannerDriver, ScanResult
from app.scanners._codetarget import CodeTarget

# Directorio con las reglas PROPIAS -- ver Dockerfile (COPY rules/semgrep
# -> esta misma ruta dentro de la imagen).
SEMGREP_RULES_DIR = os.getenv("SEMGREP_RULES_DIR", "/opt/sentinelops-semgrep-rules")

_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def build_semgrep_cmd(path: str, rules_dir: str = SEMGREP_RULES_DIR) -> list[str]:
    """Funcion pura para poder testear la construccion del comando sin
    correr semgrep de verdad. --config SIEMPRE fijo a rules_dir (ver
    docstring del modulo) -- --metrics=off desactiva ademas la
    telemetria anonima que semgrep manda por default."""
    return [
        "semgrep", "scan",
        "--config", rules_dir,
        "--json", "--quiet", "--metrics=off",
        "--timeout", "60",
        path,
    ]


def parse_semgrep_json(raw_json: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(raw_json) if raw_json.strip() else {}
    except json.JSONDecodeError:
        return findings
    for result in data.get("results", []) or []:
        extra = result.get("extra", {}) or {}
        start = result.get("start", {}) or {}
        findings.append({
            "title": f"{result.get('check_id', 'regla semgrep desconocida')} en {result.get('path', '')}",
            "description": (extra.get("message") or "")[:1000],
            "severity": _SEVERITY_MAP.get(extra.get("severity", "INFO"), "info"),
            "cve_id": None,
            "service": None,
            "file_path": result.get("path"),
            "start_line": start.get("line"),
            "rule_id": result.get("check_id"),
        })
    return findings


class SemgrepDriver(ScannerDriver):
    binary_name = "semgrep"

    async def run(self, target: str, options: dict) -> ScanResult:
        async with CodeTarget(target, clone_timeout=180, shallow=True) as ct:
            if ct.error:
                return ScanResult(raw_output="", error=ct.error)

            cmd = build_semgrep_cmd(ct.path)
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=420)
            except FileNotFoundError:
                return ScanResult(raw_output="", error="semgrep no esta instalado en este contenedor")
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ScanResult(raw_output="", error="timeout de escaneo (420s)")
            except asyncio.CancelledError:
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                raise

            raw = stdout.decode(errors="replace")
            # semgrep devuelve 1 cuando ENCONTRO hallazgos (no es un error
            # del comando) -- igual criterio que trivy/nuclei con su
            # propio codigo de salida de "hallazgos encontrados".
            if proc.returncode not in (0, 1):
                return ScanResult(raw_output=raw, error=stderr.decode(errors="replace")[:2000])
            return ScanResult(raw_output=raw[:200_000], findings=parse_semgrep_json(raw))
