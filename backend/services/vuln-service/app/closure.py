"""CIERRE VERIFICADO de vulnerabilidades: "remediada" deja de ser una declaracion y pasa a ser una prueba.

Flujo:
  1. Alguien marca una vulnerabilidad como "remediada" (triage) -> queda `closure_status = pending`.
  2. Un ciclo de fondo repite el MISMO escaneo (mismo escaner, objetivo y opciones que el que la encontro) en
     scan-service.
  3. Cuando el re-escaneo termina:
       * ya no aparece           -> `verified`   (queda firmado en la cadena de custodia: vuln.closure_verified)
       * sigue apareciendo        -> `failed`     (se reabre sola y queda en la cadena: vuln.closure_failed)
       * fallo / no termino       -> `inconclusive` (nunca se da por verificada una vulnerabilidad sin un escaneo completo)
       * no se puede repetir      -> `unsupported` (subida de archivos, agente remoto, hallazgos de nube/ASM/codigo,
                                     herramientas de observacion como falco/zeek)
  4. El MTTR "real" mide desde que se detecto hasta el cierre VERIFICADO; el "declarado" hasta que alguien dijo
     "remediada". La diferencia, y los cierres que fallaron, son lo que casi nadie mide.

Limite: "verificada" significa que el escaneo repetido ya no la detecta. Si el objetivo estaba apagado y el
escaner lo termino como "completado" sin hallazgos, podria dar un falso verificado: por eso el detalle guarda
cuantos hallazgos tuvo el re-escaneo."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody
from backend.shared.logging import configure_logging
from backend.shared.security import create_access_token
from app.models import Vulnerability, VulnStatus

logger = configure_logging("vuln-service")

SCAN_SERVICE_URL = os.getenv("SCAN_SERVICE_URL", "http://scan-service:8000")
POLL_SECONDS = int(os.getenv("VULN_CLOSURE_POLL_SECONDS", "30"))
TIMEOUT_HOURS = float(os.getenv("VULN_CLOSURE_TIMEOUT_HOURS", "6"))
MAX_CREATE_ATTEMPTS = 3

# Escaneres cuyo resultado se puede repetir sobre el mismo objetivo y comparar.
REPEATABLE_SCANNERS = {"trivy", "nuclei", "zap", "semgrep", "gitleaks"}
SYSTEM_ACTOR = "system:verificacion-de-cierre"

STATUSES = ("", "pending", "verified", "failed", "inconclusive", "unsupported")


def auto_verify() -> bool:
    return os.getenv("VULN_AUTO_VERIFY_CLOSURE", "true").strip().lower() not in ("0", "false", "no")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def hours_between(start: datetime | None, end: datetime | None) -> float | None:
    s, e = aware(start), aware(end)
    if s is None or e is None:
        return None
    return round(max(0.0, (e - s).total_seconds() / 3600), 2)


def _value(x):
    return getattr(x, "value", x)


class ClosureError(Exception):
    pass


class ScanClient:
    """Habla con scan-service con un JWT de servicio de la organizacion de la vulnerabilidad."""

    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or SCAN_SERVICE_URL).rstrip("/")

    def _headers(self, org_id: str | None) -> dict:
        return {"Authorization": "Bearer " + create_access_token("system:vuln-service", "admin", org_id=org_id)}

    async def get_job(self, org_id: str | None, job_id: str) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/scans/{job_id}", headers=self._headers(org_id))
        except httpx.HTTPError as exc:
            raise ClosureError(f"no se pudo consultar scan-service: {exc.__class__.__name__}")
        if resp.status_code == 404:
            return None
        if resp.status_code >= 300:
            raise ClosureError(f"scan-service respondio {resp.status_code}")
        return resp.json()

    async def create_job(self, org_id: str | None, payload: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(f"{self.base_url}/scans", json=payload, headers=self._headers(org_id))
        except httpx.HTTPError as exc:
            raise ClosureError(f"no se pudo pedir el re-escaneo: {exc.__class__.__name__}")
        if resp.status_code >= 300:
            detail = ""
            try:
                detail = str(resp.json().get("detail", ""))[:200]
            except ValueError:
                pass
            raise ClosureError(f"scan-service rechazo el re-escaneo ({resp.status_code}) {detail}".strip())
        return resp.json()


def get_client() -> ScanClient:
    return ScanClient()


def unsupported_reason(vuln: Vulnerability, job: dict | None) -> str:
    """Motivo por el que no se puede repetir el escaneo, o "" si se puede."""
    if not vuln.scan_job_id:
        return "el hallazgo no viene de un escaneo que se pueda repetir (nube, superficie de ataque, codigo o carga manual)"
    if job is None:
        return "el escaneo original ya no existe (o fue de un agente remoto), no se puede repetir"
    if (job.get("options") or {}).get("mode") == "upload":
        return "el hallazgo viene de un archivo subido: hay que volver a subirlo"
    scanner = str(_value(job.get("scanner_type", "")))
    if scanner not in REPEATABLE_SCANNERS:
        return "este tipo de escaner no permite repetir el escaneo para comprobar un cierre"
    return ""


def finding_matches(vuln: Vulnerability, finding: dict) -> bool:
    """Misma regla de identidad que la ingesta (services._find_existing): CVE (+ paquete si ambos lo traen) o titulo."""
    cve = str(finding.get("cve_id") or "").upper()
    if vuln.cve_id:
        if cve != vuln.cve_id.upper():
            return False
        pkg = str(finding.get("package") or "")
        return not (vuln.package and pkg) or pkg == vuln.package
    return not cve and str(finding.get("title") or "")[:500] == vuln.title


def _refs(vuln: Vulnerability, scan_job_id: str | None = None) -> list[str]:
    refs = [f"vuln:{vuln.id}"]
    if vuln.asset_id:
        refs.append(f"asset:{vuln.asset_id}")
    if scan_job_id:
        refs.append(f"scan:{scan_job_id}")
    return refs


def _base_payload(vuln: Vulnerability, scan: dict | None = None) -> dict:
    return {
        "title": vuln.title, "cve": vuln.cve_id or "", "severity": _value(vuln.severity),
        "asset_id": vuln.asset_id or "", "scanner": vuln.source_scanner,
        "detected_at": aware(vuln.created_at).isoformat() if vuln.created_at else "",
        "remediated_at": aware(vuln.remediated_at).isoformat() if vuln.remediated_at else "",
        "closure_scan_job_id": vuln.closure_scan_job_id or "",
        **({"scan_scanner": _value(scan.get("scanner_type", "")), "scan_target": str(scan.get("target", ""))[:200],
            "scan_finished_at": str(scan.get("finished_at") or ""), "scan_total_findings": len(scan.get("findings") or [])}
           if scan else {}),
    }


def mark_remediated(vuln: Vulnerability, now: datetime | None = None) -> None:
    """Se llama cuando el triage pasa la vulnerabilidad a 'remediada'."""
    vuln.remediated_at = now or _now()
    vuln.closure_scan_job_id = None
    vuln.closure_requested_at = None
    vuln.closure_attempts = 0
    vuln.verified_at = None
    vuln.closure_checked_at = None
    if auto_verify():
        vuln.closure_status = "pending"
        vuln.closure_detail = "Esperando el re-escaneo de verificacion."
    else:
        vuln.closure_status = "unsupported"
        vuln.closure_detail = "La verificacion automatica esta desactivada (VULN_AUTO_VERIFY_CLOSURE=false)."


def clear_closure(vuln: Vulnerability) -> None:
    """Se llama cuando la vulnerabilidad deja de estar 'remediada' por una decision humana."""
    vuln.remediated_at = None
    vuln.closure_status = ""
    vuln.closure_detail = ""
    vuln.closure_scan_job_id = None
    vuln.closure_requested_at = None
    vuln.verified_at = None


def request_manual(vuln: Vulnerability) -> None:
    """El usuario pide (re)verificar ahora: vuelve a 'pending' y se repite el escaneo."""
    vuln.closure_status = "pending"
    vuln.closure_detail = "Esperando el re-escaneo de verificacion."
    vuln.closure_scan_job_id = None
    vuln.closure_requested_at = None
    vuln.closure_attempts = 0
    vuln.verified_at = None


async def _emit(event_type: str, vuln: Vulnerability, actor: str, scan_job_id: str | None, payload: dict) -> None:
    await custody.record_event(
        event_type, service="vuln-service", organization_id=vuln.organization_id, actor=actor,
        subject_type="vuln", subject_id=vuln.id, refs=_refs(vuln, scan_job_id), payload=payload)


def _finish(vuln: Vulnerability, status: str, detail: str, now: datetime) -> None:
    vuln.closure_status = status
    vuln.closure_detail = detail[:1000]
    vuln.closure_checked_at = now


async def step(db: AsyncSession, vuln: Vulnerability, client: ScanClient, now: datetime | None = None) -> str:
    """Avanza UNA vulnerabilidad pendiente un paso. Devuelve su closure_status al terminar el paso."""
    now = now or _now()
    org = vuln.organization_id
    try:
        if not vuln.closure_scan_job_id:
            original = await client.get_job(org, vuln.scan_job_id) if vuln.scan_job_id else None
            reason = unsupported_reason(vuln, original)
            if reason:
                _finish(vuln, "unsupported", "No se puede verificar automaticamente: " + reason + ".", now)
                return vuln.closure_status
            payload = {
                "name": f"Verificacion de cierre: {vuln.title}"[:255], "scanner_type": _value(original["scanner_type"]),
                "target": original["target"], "asset_id": vuln.asset_id, "options": original.get("options") or {},
            }
            try:
                job = await client.create_job(org, payload)
            except ClosureError as exc:
                vuln.closure_attempts = (vuln.closure_attempts or 0) + 1
                if vuln.closure_attempts >= MAX_CREATE_ATTEMPTS:
                    _finish(vuln, "inconclusive", f"No se pudo pedir el re-escaneo ({exc}). Podes reintentar a mano.", now)
                else:
                    vuln.closure_detail = f"Reintentando pedir el re-escaneo ({exc})."
                return vuln.closure_status
            vuln.closure_scan_job_id = job["id"]
            vuln.closure_requested_at = now
            vuln.closure_detail = "Re-escaneo en curso."
            await _emit("vuln.closure_requested", vuln, SYSTEM_ACTOR, job["id"], {
                **_base_payload(vuln), "scan_scanner": payload["scanner_type"], "scan_target": payload["target"][:200]})
            return vuln.closure_status

        job = await client.get_job(org, vuln.closure_scan_job_id)
    except ClosureError as exc:
        vuln.closure_detail = f"No se pudo consultar el re-escaneo ({exc}); se reintenta."
        return vuln.closure_status

    if job is None:
        _finish(vuln, "inconclusive", "El re-escaneo ya no existe en scan-service (se borro). Podes reintentar.", now)
        return vuln.closure_status
    state = str(_value(job.get("status", "")))
    if state in ("pending", "running"):
        waited = aware(vuln.closure_requested_at)
        if waited and now - waited > timedelta(hours=TIMEOUT_HOURS):
            _finish(vuln, "inconclusive", f"El re-escaneo no termino en {TIMEOUT_HOURS:g} horas. Podes reintentar.", now)
        return vuln.closure_status
    if state != "completed":
        err = str(job.get("error_message") or "")[:300]
        _finish(vuln, "inconclusive", f"El re-escaneo no se completo ({state}){': ' + err if err else ''}. No se da por verificada.", now)
        return vuln.closure_status

    findings = job.get("findings") or []
    still = [f for f in findings if finding_matches(vuln, f)]
    payload = _base_payload(vuln, job)
    if still:
        _finish(vuln, "failed", f"El re-escaneo la volvio a detectar ({len(still)} coincidencia/s): el cierre no se sostiene.", now)
        vuln.status = VulnStatus.open
        vuln.triage_note = (vuln.triage_note + "\n" if vuln.triage_note else "") + (
            f"[{now.date().isoformat()}] Reabierta: el re-escaneo de verificacion la volvio a detectar.")
        vuln.triaged_by = SYSTEM_ACTOR
        vuln.updated_at = now
        await _emit("vuln.closure_failed", vuln, SYSTEM_ACTOR, vuln.closure_scan_job_id, {
            **payload, "matches": len(still), "from": "remediated", "to": "open"})
    else:
        vuln.verified_at = now
        _finish(vuln, "verified", f"El re-escaneo termino sin esta vulnerabilidad ({len(findings)} hallazgos en total).", now)
        await _emit("vuln.closure_verified", vuln, SYSTEM_ACTOR, vuln.closure_scan_job_id, {
            **payload, "verified_at": now.isoformat(),
            "mttr_real_hours": hours_between(vuln.created_at, now), "mttr_declared_hours": hours_between(vuln.created_at, vuln.remediated_at)})
    return vuln.closure_status


async def process_pending(session_factory, client: ScanClient | None = None, limit: int = 50) -> int:
    """Una vuelta del ciclo: avanza todas las vulnerabilidades pendientes. Devuelve cuantas toco."""
    client = client or get_client()
    touched = 0
    async with session_factory() as db:
        rows = (await db.execute(
            select(Vulnerability).where(Vulnerability.closure_status == "pending").order_by(Vulnerability.updated_at).limit(limit)
        )).scalars().all()
        for vuln in rows:
            try:
                await step(db, vuln, client)
                touched += 1
            except Exception as exc:  # una vulnerabilidad rara no puede frenar a las demas
                logger.warning("fallo la verificacion de cierre", extra={"vuln_id": vuln.id, "error": str(exc)})
        await db.commit()
    return touched


async def loop(session_factory) -> None:
    while True:
        try:
            await process_pending(session_factory)
        except Exception:
            logger.exception("fallo el ciclo de verificacion de cierres")
        await asyncio.sleep(POLL_SECONDS)


async def stats(db: AsyncSession, organization_id: str) -> dict:
    rows = (await db.execute(select(Vulnerability).where(
        Vulnerability.organization_id == organization_id,
        (Vulnerability.status == VulnStatus.remediated) | (Vulnerability.closure_status != "")))).scalars().all()
    counts = {s: 0 for s in STATUSES if s}
    remediated = [v for v in rows if v.status == VulnStatus.remediated]
    declared = [h for v in remediated if (h := hours_between(v.created_at, v.remediated_at)) is not None]
    real = [h for v in rows if v.closure_status == "verified" and (h := hours_between(v.created_at, v.verified_at)) is not None]
    by_sev: dict[str, dict] = {}
    for v in rows:
        if v.closure_status:
            counts[v.closure_status] = counts.get(v.closure_status, 0) + 1
        sev = _value(v.severity)
        b = by_sev.setdefault(sev, {"verified": 0, "failed": 0, "pending": 0, "unverified": 0, "real_hours": [], "declared_hours": []})
        if v.closure_status == "verified":
            b["verified"] += 1
            h = hours_between(v.created_at, v.verified_at)
            if h is not None:
                b["real_hours"].append(h)
        elif v.closure_status == "failed":
            b["failed"] += 1
        elif v.closure_status == "pending":
            b["pending"] += 1
        elif v.status == VulnStatus.remediated:
            b["unverified"] += 1
        if v.status == VulnStatus.remediated and (h := hours_between(v.created_at, v.remediated_at)) is not None:
            b["declared_hours"].append(h)

    def avg(values):
        return round(sum(values) / len(values), 2) if values else None

    decided = counts["verified"] + counts["failed"]
    return {
        "counts": counts,
        "remediated_total": len(remediated),
        "remediated_unverified": sum(1 for v in remediated if v.closure_status in ("", "unsupported", "inconclusive")),
        "mttr_declared_hours": avg(declared), "mttr_real_hours": avg(real),
        "false_closure_rate_pct": round(100 * counts["failed"] / decided, 1) if decided else None,
        "by_severity": {k: {"verified": b["verified"], "failed": b["failed"], "pending": b["pending"], "unverified": b["unverified"],
                            "mttr_real_hours": avg(b["real_hours"]), "mttr_declared_hours": avg(b["declared_hours"])}
                        for k, b in sorted(by_sev.items())},
    }
