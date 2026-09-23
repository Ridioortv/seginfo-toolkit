"""Driver de Nuclei: deteccion basada en plantillas (CVEs conocidos,
exposiciones, malas configuraciones, huella tecnologica). Se excluyen
explicitamente las categorias 'dos', 'fuzz' e 'intrusive': solo se
ejecutan plantillas de deteccion pasiva/no invasiva. NUNCA se habilitan
plantillas de explotacion activa."""
import asyncio
import json
from app.scanners.base import ScannerDriver, ScanResult

_EXCLUDED_TAGS = "dos,fuzz,intrusive"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiDriver(ScannerDriver):
    binary_name = "nuclei"

    async def run(self, target: str, options: dict) -> ScanResult:
        cmd = [
            "nuclei", "-target", target, "-etags", _EXCLUDED_TAGS,
            "-jsonl", "-silent", "-no-interactsh", "-timeout", "10",
        ]
        tags = options.get("tags")
        if isinstance(tags, str) and tags:
            safe_tags = ",".join(t.strip() for t in tags.split(",") if t.strip().isalnum())
            if safe_tags:
                cmd += ["-tags", safe_tags]

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

        raw = stdout.decode(errors="replace")
        if proc.returncode not in (0, 1) and not raw.strip():
            return ScanResult(raw_output=raw, error=stderr.decode(errors="replace")[:2000])

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
