"""Driver de Gitleaks: deteccion de secretos/credenciales commiteados
por error en un repositorio de codigo, en TODO el historial de git
cuando el target es un repo real (un secreto borrado en un commit
posterior sigue expuesto en el historial) -- puramente de deteccion,
nunca modifica el repositorio ni ejecuta nada de su contenido.

target: una URL git clonable (https://...) o un path local ya
existente (util para el agente remoto, que puede escanear un repo que
el usuario ya tiene clonado en su propia maquina). Ver
app/scanners/_codetarget.py.

Licencia: Gitleaks es MIT (Zachary Rice) -- se invoca como binario
externo via subprocess, igual que trivy/nuclei. Mismo patron ya
probado en produccion en coderepo-service
(app/services.py::_run_gitleaks de ese servicio), aca adaptado al
modelo generico target+scanner_type de scan-service (coderepo-service
sigue siendo el flujo dedicado para "todos los repos de la
organizacion, escaneados periodicamente"; esto es para un target
puntual desde Escaneos programados/remotos)."""
import asyncio
import json
import os
from app.scanners.base import ScannerDriver, ScanResult
from app.scanners._codetarget import CodeTarget

_SEVERITY_BY_RULE_MARKER = (
    (("private-key", "aws", "gcp", "azure", "service-account"), "critical"),
    (("token", "api-key", "apikey", "secret", "password", "generic"), "high"),
)


def classify_gitleaks_severity(rule_id: str) -> str:
    rule = (rule_id or "").lower()
    for markers, severity in _SEVERITY_BY_RULE_MARKER:
        if any(marker in rule for marker in markers):
            return severity
    return "medium"


def redact_secret_match(raw: str) -> str:
    """JAMAS se persiste ni se muestra el secreto real -- solo esta
    version con relleno de puntos medios."""
    raw = raw or ""
    if len(raw) <= 6:
        return "••••"
    padding = min(len(raw) - 5, 20)
    return f"{raw[:3]}{chr(0x2022) * padding}{raw[-2:]}"


def parse_gitleaks_report(raw_json: str) -> list[dict]:
    """Funcion pura, testeable sin correr gitleaks de verdad.
    --report-format json devuelve una lista (puede ser [] sin
    hallazgos)."""
    try:
        data = json.loads(raw_json) if raw_json and raw_json.strip() else []
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    findings: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("RuleID", "")
        file_path = item.get("File", "")
        findings.append({
            "title": f"Secreto detectado ({rule_id or 'regla desconocida'}) en {file_path}",
            "description": item.get("Description", ""),
            "severity": classify_gitleaks_severity(rule_id),
            "cve_id": None,
            "service": None,
            "file_path": file_path,
            "start_line": item.get("StartLine"),
            "commit_hash": item.get("Commit", ""),
            "rule_id": rule_id,
            "match_redacted": redact_secret_match(item.get("Secret") or item.get("Match") or ""),
        })
    return findings


def _build_gitleaks_cmd(source_path: str, report_path: str, no_git: bool) -> list[str]:
    """Funcion pura para poder testear la construccion del comando sin
    correr gitleaks de verdad. --exit-code 0 es CLAVE: gitleaks sale
    con codigo 1 si encuentra leaks por default -- sin esto este
    driver interpretaria un hallazgo real como si el comando hubiera
    fallado."""
    cmd = [
        "gitleaks", "detect",
        "--source", source_path,
        "--report-format", "json",
        "--report-path", report_path,
        "--exit-code", "0",
        "--no-banner",
    ]
    if no_git:
        # target era un directorio comun (no un repo git real, ej. un
        # path que el agente remoto escanea directo) -- sin --no-git,
        # gitleaks "detect" falla con "ERRO ... git log ..." porque
        # intenta leer historial de git que no existe.
        cmd.append("--no-git")
    return cmd


class GitleaksDriver(ScannerDriver):
    binary_name = "gitleaks"

    async def run(self, target: str, options: dict) -> ScanResult:
        async with CodeTarget(target, clone_timeout=180, shallow=False) as ct:
            if ct.error:
                return ScanResult(raw_output="", error=ct.error)

            import tempfile
            report_fd, report_path = tempfile.mkstemp(prefix="gitleaks-report-", suffix=".json")
            os.close(report_fd)
            try:
                no_git = not os.path.isdir(os.path.join(ct.path, ".git"))
                cmd = _build_gitleaks_cmd(ct.path, report_path, no_git)
                proc = None
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                except FileNotFoundError:
                    return ScanResult(raw_output="", error="gitleaks no esta instalado en este contenedor")
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    return ScanResult(raw_output="", error="timeout de escaneo (300s)")
                except asyncio.CancelledError:
                    if proc is not None:
                        proc.kill()
                        await proc.wait()
                    raise

                if proc.returncode != 0:
                    return ScanResult(raw_output="", error=stderr.decode(errors="replace")[:2000])

                try:
                    with open(report_path, "r", encoding="utf-8") as fh:
                        raw_json = fh.read()
                except OSError:
                    raw_json = "[]"
                return ScanResult(raw_output=raw_json[:200_000], findings=parse_gitleaks_report(raw_json))
            finally:
                try:
                    os.remove(report_path)
                except OSError:
                    pass
