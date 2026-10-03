"""Driver de Zeek: captura y analisis PASIVO de trafico de red durante
una ventana de tiempo FIJA (configurable, ver options.duration_minutes
y app/scanners/_duration.py) -- a diferencia de trivy/nuclei/zap/
semgrep/gitleaks/yara (que escanean un target puntual y terminan),
Zeek es una herramienta de monitoreo CONTINUO por naturaleza. Se la
encaja aca como un "job de duracion fija" por decision explicita de
producto (Manu, 2026): corre durante N minutos y reporta lo que haya
detectado en esa ventana, como si fuera un escaneo mas.

Esto requiere que el contenedor que lo ejecuta tenga capacidades de
captura de paquetes (NET_RAW/NET_ADMIN, ver docker-compose.yml) que
NINGUN otro escaner de esta plataforma necesita -- si faltan, Zeek
falla al arrancar y el job termina con un error claro (nunca se
degrada en silencio a "no encontro nada", ver el chequeo de
returncode mas abajo).

target: el nombre de la interfaz de red a capturar (ej. "eth0"), o el
literal "auto" para que el driver intente detectar automaticamente la
primera interfaz que no sea loopback.

Licencia: BSD-3-Clause (Zeek Project / ICSI) -- invocado como binario
externo via subprocess, igual que trivy/nuclei."""
import asyncio
import json
import os
import shutil
import tempfile
from app.scanners.base import ScannerDriver, ScanResult
from app.scanners._duration import resolve_duration_seconds

# Zeek clasifica sus propios hallazgos en "notice types" (ver su
# framework de notificaciones, cargado via la politica "local" que usa
# este driver) -- esta es una clasificacion PROPIA, aproximada, de
# severidad para los tipos mas comunes que trae esa politica por
# defecto.
_NOTE_SEVERITY_BY_KEYWORD = (
    # "Scan::" cubre los notice types reales del script scan.zeek
    # (Scan::Address_Scan, Scan::Port_Scan) -- con el namespace completo,
    # no una adivinanza camelCase sin el separador "::" real de Zeek.
    (("Scan::",), "high"),
    (("SSL::", "Weird::"), "medium"),
)


def classify_zeek_notice(note_type: str) -> str:
    for keywords, severity in _NOTE_SEVERITY_BY_KEYWORD:
        if any(k in (note_type or "") for k in keywords):
            return severity
    return "low"


def resolve_interface(target: str, list_interfaces=None) -> str | None:
    """Funcion pura (list_interfaces inyectable para tests): si target
    no es 'auto', se usa tal cual. Si es 'auto', se devuelve la primera
    interfaz distinta de 'lo' que reporte list_interfaces (por defecto,
    os.listdir sobre /sys/class/net)."""
    target = (target or "").strip()
    if target and target.lower() != "auto":
        return target
    lister = list_interfaces or (lambda: os.listdir("/sys/class/net"))
    try:
        candidates = [d for d in lister() if d != "lo"]
    except OSError:
        return None
    return candidates[0] if candidates else None


def parse_notice_log(path: str) -> list[dict]:
    findings: list[dict] = []
    if not os.path.exists(path):
        return findings
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                note = event.get("note", "notice desconocido")
                findings.append({
                    "title": f"Zeek notice: {note}",
                    "description": (event.get("msg") or "")[:1000],
                    "severity": classify_zeek_notice(note),
                    "cve_id": None,
                    "service": event.get("id.resp_h") or event.get("id.orig_h"),
                })
    except OSError:
        pass
    return findings


def summarize_conn_log(path: str) -> str:
    if not os.path.exists(path):
        return "(sin conn.log -- no se vio trafico durante la ventana de captura)"
    total = 0
    unique_hosts: set = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                for key in ("id.orig_h", "id.resp_h"):
                    if event.get(key):
                        unique_hosts.add(event[key])
    except OSError:
        return "(error leyendo conn.log)"
    return f"{total} conexion(es) observadas entre {len(unique_hosts)} host(s) unico(s) durante la ventana de captura."


class ZeekDriver(ScannerDriver):
    binary_name = "zeek"

    async def run(self, target: str, options: dict) -> ScanResult:
        interface = resolve_interface(target)
        if not interface:
            return ScanResult(
                raw_output="",
                error=(
                    f"no se pudo resolver una interfaz de red valida a partir de target='{target}' "
                    "(usa el nombre de una interfaz, ej. 'eth0', o 'auto')"
                ),
            )
        duration_seconds = resolve_duration_seconds(options or {})
        workdir = tempfile.mkdtemp(prefix="zeek-capture-")
        try:
            cmd = ["zeek", "-i", interface, "-C", "LogAscii::use_json=T", "local"]
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, cwd=workdir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration_seconds)
                    # Zeek termino SOLO antes de agotarse la ventana --
                    # Zeek en modo "-i" vive para siempre hasta que lo
                    # matan, asi que terminar antes siempre es una falla
                    # real (permisos insuficientes, interfaz invalida,
                    # etc.), nunca "termino de capturar".
                    if proc.returncode != 0:
                        return ScanResult(
                            raw_output=stdout.decode(errors="replace")[:5000],
                            error=(
                                "zeek termino antes de completar la ventana de captura (probablemente sin "
                                "permisos NET_RAW/NET_ADMIN en este contenedor, ver docker-compose.yml): "
                                + stderr.decode(errors="replace")[:1800]
                            ),
                        )
                except asyncio.TimeoutError:
                    # Fin ESPERADO de la ventana fija -- ver docstring del
                    # modulo. Se mata el proceso y se reportan los logs
                    # acumulados hasta ahora como resultado del job.
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=10)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
            except FileNotFoundError:
                return ScanResult(raw_output="", error="zeek no esta instalado en este contenedor")
            except asyncio.CancelledError:
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                raise

            notice_findings = parse_notice_log(os.path.join(workdir, "notice.log"))
            summary = summarize_conn_log(os.path.join(workdir, "conn.log"))
            raw_output = f"Captura en interfaz '{interface}' durante {duration_seconds // 60} minuto(s).\n{summary}"
            return ScanResult(raw_output=raw_output[:200_000], findings=notice_findings)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
