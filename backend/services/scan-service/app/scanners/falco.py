"""Driver de Falco: monitoreo de eventos de runtime (shells inesperadas
dentro de un contenedor, escritura en binarios del sistema, escalada
de privilegios, etc.) durante una ventana de tiempo FIJA -- misma
decision de producto que Zeek (ver docstring de app/scanners/zeek.py):
Falco es una herramienta de monitoreo CONTINUO por naturaleza, aca se
la encaja como "job de duracion fija" via su propio flag -M (Falco se
para solo despues de ese tiempo, no hace falta que este driver lo mate
a mano).

Requiere acceso a eBPF/kernel del host (capacidades elevadas, ver
docker-compose.yml) que Docker Desktop puede o no exponer segun la
version/el backend (WSL2 vs Hyper-V) -- si Falco no puede cargar su
driver, termina con un error claro al toque (nunca se degrada en
silencio a "no encontro nada"). Motor fijado explicitamente a
'modern_ebpf' (usa libbpf+BTF del kernel, no necesita compilar ni
descargar un driver de kernel aparte en runtime).

target: una etiqueta libre que describe que se esta monitoreando (ej.
"host-produccion") -- Falco monitorea TODO el nodo/contenedor donde
corre, no un target puntual, asi que este valor es solo descriptivo y
no se usa en el comando.

Licencia: Apache 2.0 (The Falco Authors / CNCF); las reglas por
defecto (falco_rules.yaml, tambien Apache 2.0) se usan tal cual, sin
modificar -- invocado como binario externo via subprocess, igual que
trivy/nuclei."""
import json
from app.scanners.base import ScannerDriver, ScanResult
from app.scanners._duration import resolve_duration_seconds, run_for_fixed_duration

_PRIORITY_SEVERITY_MAP = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "informational": "info",
    "debug": "info",
}


def parse_falco_jsonl(raw: str) -> list[dict]:
    findings: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "rule" not in event:
            continue  # linea de log propia de falco (arranque, warnings internos), no una alerta
        priority = (event.get("priority") or "").lower()
        findings.append({
            "title": f"Falco: {event.get('rule', 'regla desconocida')}",
            "description": (event.get("output") or "")[:1000],
            "severity": _PRIORITY_SEVERITY_MAP.get(priority, "medium"),
            "cve_id": None,
            "service": (event.get("output_fields") or {}).get("container.name"),
        })
    return findings


class FalcoDriver(ScannerDriver):
    binary_name = "falco"

    async def run(self, target: str, options: dict) -> ScanResult:
        duration_seconds = resolve_duration_seconds(options or {})
        cmd = ["falco", "-M", str(duration_seconds), "-o", "engine.kind=modern_ebpf", "-o", "json_output=true"]
        try:
            # La ventana la controla run_for_fixed_duration (no solo -M): al vencer, SIGTERM
            # y se lee lo capturado; asi el escaneo siempre termina y no se pierde nada.
            returncode, stdout, stderr, stopped = await run_for_fixed_duration(cmd, duration_seconds)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="falco no esta instalado en este contenedor")

        raw = stdout.decode(errors="replace")
        if returncode not in (0, None) and not stopped and not raw.strip():
            return ScanResult(
                raw_output="",
                error=(
                    "falco no pudo arrancar (probablemente sin acceso a eBPF/kernel en este contenedor, "
                    "ver docker-compose.yml): " + stderr.decode(errors="replace")[:1800]
                ),
            )
        return ScanResult(
            raw_output=raw[:200_000] or f"monitoreo de runtime durante {max(1, duration_seconds // 60)} minuto(s), sin eventos.",
            findings=parse_falco_jsonl(raw),
        )
