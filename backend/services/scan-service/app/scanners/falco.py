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
import asyncio
import json
from app.scanners.base import ScannerDriver, ScanResult
from app.scanners._duration import resolve_duration_seconds

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
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            # Margen de 30s sobre -M: Falco se para solo a los
            # duration_seconds pedidos, este timeout de afuera es solo
            # una red de contencion si por lo que sea no lo hiciera.
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration_seconds + 30)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="falco no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ScanResult(
                raw_output="",
                error=f"falco no termino solo tras {duration_seconds + 30}s -- se lo mato a la fuerza",
            )
        except asyncio.CancelledError:
            if proc is not None:
                proc.kill()
                await proc.wait()
            raise

        raw = stdout.decode(errors="replace")
        if proc.returncode != 0 and not raw.strip():
            return ScanResult(
                raw_output="",
                error=(
                    "falco no pudo arrancar (probablemente sin acceso a eBPF/kernel en este contenedor, "
                    "ver docker-compose.yml): " + stderr.decode(errors="replace")[:1800]
                ),
            )
        return ScanResult(
            raw_output=raw[:200_000] or f"monitoreo de runtime durante {duration_seconds // 60} minuto(s), sin eventos.",
            findings=parse_falco_jsonl(raw),
        )
