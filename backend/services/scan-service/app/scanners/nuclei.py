"""Driver de Nuclei: deteccion basada en plantillas (CVEs conocidos,
exposiciones, malas configuraciones, huella tecnologica). Se excluyen
explicitamente las categorias 'dos', 'fuzz' e 'intrusive': solo se
ejecutan plantillas de deteccion pasiva/no invasiva. NUNCA se habilitan
plantillas de explotacion activa.

Las plantillas se descargan una vez al construir la imagen (ver Dockerfile:
`nuclei -update-templates`) y se refrescan en segundo plano cada 12hs (ver
app/services.py::refresh_nuclei_templates, registrado en app/main.py). Por
eso cada escaneo corre con -duc (disable update check): sin esto, nuclei
chequeaba/actualizaba plantillas en CADA escaneo individual, que era la
causa principal de que "tardara mucho"."""
import asyncio
import json
from app.scanners.base import ScannerDriver, ScanResult, clean_stderr

_EXCLUDED_TAGS = "dos,fuzz,intrusive"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def _build_nuclei_cmd(target: str, options: dict) -> list[str]:
    """Funcion pura (sin I/O) para poder testear la construccion del
    comando sin ejecutar nuclei de verdad."""
    cmd = [
        "nuclei", "-target", target, "-etags", _EXCLUDED_TAGS,
        "-jsonl", "-silent", "-no-interactsh", "-timeout", "10", "-duc",
    ]
    tags = options.get("tags")
    if isinstance(tags, str) and tags:
        safe_tags = ",".join(t.strip() for t in tags.split(",") if t.strip().isalnum())
        if safe_tags:
            cmd += ["-tags", safe_tags]
    return cmd


class NucleiDriver(ScannerDriver):
    binary_name = "nuclei"

    async def run(self, target: str, options: dict) -> ScanResult:
        cmd = _build_nuclei_cmd(target, options)

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="nuclei no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ScanResult(raw_output="", error="timeout de escaneo (600s)")
        except asyncio.CancelledError:
            # Sin este kill(), nuclei sigue corriendo huerfano dentro del
            # contenedor aunque el job ya haya quedado cancelado.
            if proc is not None:
                proc.kill()
                await proc.wait()
            raise

        raw = stdout.decode(errors="replace")
        # nuclei sale con 0 aunque no encuentre nada Y aunque encuentre
        # hallazgos; un codigo != 0 sin NADA en stdout es un fallo real
        # (ej. "no templates provided for scan" cuando el volumen de
        # plantillas esta vacio, exit 1). Antes el 1 se tomaba por
        # "hubo hallazgos" y el job terminaba "completado, 0 hallazgos".
        if proc.returncode != 0 and not raw.strip():
            err = clean_stderr(stderr.decode(errors="replace"))
            if "no templates" in err.lower():
                err = (
                    "nuclei no tiene plantillas instaladas (volumen nuclei_templates vacio). "
                    "Corre: docker compose exec scan-service nuclei -update-templates  -- detalle: " + err
                )[:2000]
            return ScanResult(raw_output=raw, error=err or f"nuclei termino con codigo {proc.returncode} sin salida")

        return ScanResult(raw_output=raw, findings=_parse_nuclei_jsonl(raw))


def _parse_nuclei_jsonl(raw_jsonl: str) -> list[dict]:
    findings: list[dict] = []
    for line in raw_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = event.get("info", {})
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id") or []
        findings.append(
            {
                "title": info.get("name", event.get("template-id", "hallazgo nuclei")),
                "description": (info.get("description") or "")[:1000],
                "severity": _SEVERITY_MAP.get(info.get("severity", "unknown"), "info"),
                "cve_id": cve_ids[0] if cve_ids else None,
                "service": event.get("matched-at"),
            }
        )
    return findings
