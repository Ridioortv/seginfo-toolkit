"""Business logic for report-service: agregacion de datos ya existentes en
otros servicios (vuln-service, siem-service, case-service, purple-service)
para armar reportes ejecutivos/de cumplimiento. NUNCA inventa datos: si un
servicio fuente no responde, esa seccion queda vacia con su error registrado
en `errors`, y el resto del reporte se genera igual (best-effort)."""
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import GeneratedReport

logger = configure_logging("report-service")

VULN_SERVICE_URL = os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000")
SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")
CASE_SERVICE_URL = os.getenv("CASE_SERVICE_URL", "http://case-service:8000")
PURPLE_SERVICE_URL = os.getenv("PURPLE_SERVICE_URL", "http://purple-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _fetch(client: httpx.AsyncClient, url: str, headers: dict, errors: list[str]) -> dict | list | None:
    try:
        response = await client.get(url, headers=headers, timeout=10.0)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as exc:
        logger.warning("fallo al consultar servicio fuente para reporte", extra={"url": url, "error": str(exc)})
        errors.append(f"{url}: {exc}")
        return None


async def _collect_vulnerabilities(client: httpx.AsyncClient, headers: dict, errors: list[str]) -> dict:
    stats = await _fetch(client, f"{VULN_SERVICE_URL}/vulnerabilities/stats", headers, errors)
    return {"stats": stats}


async def _collect_incidents(client: httpx.AsyncClient, headers: dict, errors: list[str]) -> dict:
    cases = await _fetch(client, f"{CASE_SERVICE_URL}/cases", headers, errors)
    alerts = await _fetch(client, f"{SIEM_SERVICE_URL}/alerts", headers, errors)
    open_cases = [c for c in (cases or []) if c.get("status") in ("open", "in_progress")]
    now_iso = _now().isoformat()
    breached = []
    for c in open_cases:
        sla_due = c.get("sla_due_at")
        if sla_due and sla_due < now_iso:
            breached.append(c)
    return {
        "total_cases": len(cases) if cases is not None else None,
        "open_cases": len(open_cases),
        "sla_breached_cases": len(breached),
        "total_alerts": len(alerts) if alerts is not None else None,
        "cases": cases,
        "alerts": alerts,
    }


async def _collect_attack_coverage(client: httpx.AsyncClient, headers: dict, errors: list[str]) -> dict:
    coverage = await _fetch(client, f"{PURPLE_SERVICE_URL}/coverage/overall", headers, errors)
    return {"coverage": coverage}


async def _collect_executive_summary(client: httpx.AsyncClient, headers: dict, errors: list[str]) -> dict:
    vulns = await _collect_vulnerabilities(client, headers, errors)
    incidents = await _collect_incidents(client, headers, errors)
    coverage = await _collect_attack_coverage(client, headers, errors)
    return {
        "vulnerabilities": vulns.get("stats"),
        "open_cases": incidents.get("open_cases"),
        "sla_breached_cases": incidents.get("sla_breached_cases"),
        "total_alerts": incidents.get("total_alerts"),
        "attack_coverage_pct": (coverage.get("coverage") or {}).get("coverage_pct"),
        "attack_gaps": (coverage.get("coverage") or {}).get("gaps"),
    }


_COLLECTORS = {
    "vulnerabilities": _collect_vulnerabilities,
    "incidents": _collect_incidents,
    "attack_coverage": _collect_attack_coverage,
    "executive_summary": _collect_executive_summary,
}


async def generate_report(db: AsyncSession, report_type: str, auth_header: str | None, generated_by: str) -> GeneratedReport:
    """Genera un reporte reenviando el token del usuario que lo solicito a
    los servicios fuente (mismo nivel de permisos que ya tiene ese usuario,
    nunca credenciales de servicio elevadas)."""
    headers = {"Authorization": auth_header} if auth_header else {}
    errors: list[str] = []
    async with httpx.AsyncClient() as client:
        collector = _COLLECTORS[report_type]
        data = await collector(client, headers, errors)
    report = GeneratedReport(report_type=report_type, generated_by=generated_by, data=data, errors=errors)
    db.add(report)
    await db.flush()
    return report


async def list_reports(db: AsyncSession, report_type: str | None = None) -> list[GeneratedReport]:
    query = select(GeneratedReport)
    if report_type:
        query = query.where(GeneratedReport.report_type == report_type)
    result = await db.execute(query.order_by(GeneratedReport.created_at.desc()))
    return list(result.scalars().all())


async def get_report(db: AsyncSession, report_id: str) -> GeneratedReport | None:
    result = await db.execute(select(GeneratedReport).where(GeneratedReport.id == report_id))
    return result.scalar_one_or_none()
