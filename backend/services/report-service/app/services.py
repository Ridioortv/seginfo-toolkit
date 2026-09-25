"""Business logic for report-service: agregacion de datos ya existentes en
otros servicios (vuln-service, siem-service, case-service, purple-service)
para armar reportes ejecutivos/de cumplimiento. NUNCA inventa datos: si un
servicio fuente no responde, esa seccion queda vacia con su error registrado
en `errors`, y el resto del reporte se genera igual (best-effort)."""
import base64
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from backend.shared.security import create_access_token
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.export import export_to_pdf
from app.models import GeneratedReport, ReportSchedule

logger = configure_logging("report-service")

VULN_SERVICE_URL = os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000")
SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")
CASE_SERVICE_URL = os.getenv("CASE_SERVICE_URL", "http://case-service:8000")
PURPLE_SERVICE_URL = os.getenv("PURPLE_SERVICE_URL", "http://purple-service:8000")
NOTIFICATION_SERVICE_URL = os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8000")

_REPORT_TITLES = {
    "executive_summary": "Resumen ejecutivo",
    "vulnerabilities": "Vulnerabilidades",
    "incidents": "Incidentes",
    "attack_coverage": "Cobertura ATT&CK",
}


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


async def generate_report(
    db: AsyncSession, report_type: str, auth_header: str | None, generated_by: str, organization_id: str
) -> GeneratedReport:
    """Genera un reporte reenviando el token del usuario que lo solicito a
    los servicios fuente (mismo nivel de permisos que ya tiene ese usuario,
    nunca credenciales de servicio elevadas) -- ese mismo token ya lleva el
    org_id de ese usuario, asi que cada servicio fuente devuelve solo datos
    de ese tenant."""
    headers = {"Authorization": auth_header} if auth_header else {}
    errors: list[str] = []
    async with httpx.AsyncClient() as client:
        collector = _COLLECTORS[report_type]
        data = await collector(client, headers, errors)
    report = GeneratedReport(
        organization_id=organization_id, report_type=report_type, generated_by=generated_by, data=data, errors=errors
    )
    db.add(report)
    await db.flush()
    return report


async def list_reports(db: AsyncSession, organization_id: str, report_type: str | None = None) -> list[GeneratedReport]:
    query = select(GeneratedReport).where(GeneratedReport.organization_id == organization_id)
    if report_type:
        query = query.where(GeneratedReport.report_type == report_type)
    result = await db.execute(query.order_by(GeneratedReport.created_at.desc()))
    return list(result.scalars().all())


async def get_report(db: AsyncSession, report_id: str, organization_id: str) -> GeneratedReport | None:
    result = await db.execute(
        select(GeneratedReport).where(
            GeneratedReport.id == report_id, GeneratedReport.organization_id == organization_id
        )
    )
    return result.scalar_one_or_none()


async def delete_report(db: AsyncSession, report: GeneratedReport) -> None:
    await db.delete(report)
    await db.flush()


async def create_schedule(db: AsyncSession, payload, actor: str, organization_id: str) -> ReportSchedule:
    schedule = ReportSchedule(
        organization_id=organization_id,
        report_type=payload.report_type,
        notification_channel_id=payload.notification_channel_id,
        frequency=payload.frequency,
        hour=payload.hour,
        minute=payload.minute,
        day_of_week=payload.day_of_week,
        created_by=actor,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


async def list_schedules(db: AsyncSession, organization_id: str | None = None) -> list[ReportSchedule]:
    """organization_id es opcional SOLO para el uso interno del lifespan
    (re-registrar todos los jobs de todas las organizaciones al arrancar el
    scheduler en proceso) -- todo endpoint HTTP siempre lo pasa."""
    query = select(ReportSchedule)
    if organization_id is not None:
        query = query.where(ReportSchedule.organization_id == organization_id)
    result = await db.execute(query.order_by(ReportSchedule.created_at.desc()))
    return list(result.scalars().all())


async def get_schedule(db: AsyncSession, schedule_id: str, organization_id: str) -> ReportSchedule | None:
    schedule = await db.get(ReportSchedule, schedule_id)
    if schedule is None or schedule.organization_id != organization_id:
        return None
    return schedule


async def set_schedule_enabled(db: AsyncSession, schedule: ReportSchedule, enabled: bool) -> ReportSchedule:
    schedule.enabled = enabled
    await db.flush()
    return schedule


async def delete_schedule(db: AsyncSession, schedule: ReportSchedule) -> None:
    await db.delete(schedule)
    await db.flush()


def summarize_notify_result(results: list[dict]) -> str:
    """Determina el estado REAL de una corrida de reporte programado a
    partir de los resultados por canal que devuelve POST /notify de
    notification-service (NotifyResult.results, una lista de dicts con al
    menos 'status'). Funcion pura, sin I/O, para poder testearla sin
    levantar httpx/DB.

    Antes de este fix, run_scheduled_report solo miraba si la llamada
    HTTP a /notify daba 2xx (`response.raise_for_status()`) e ignoraba el
    body -- pero notify() siempre devuelve 200 aunque no haya enviado
    nada, en dos casos que este fix cubre:

    - `results` vacio: ningun canal matcheo el `channel_ids` pedido (por
      ejemplo, el canal de email de la regla fue deshabilitado o
      borrado despues de crear la regla) -> "failed", nadie recibe nada.
    - algun resultado con status == "failed" (ej. SMTP_HOST mal
      configurado, credenciales invalidas) -> "failed", aunque la
      llamada HTTP a notification-service haya sido 200.

    Si todos los resultados son "sent" y/o "simulated" -> "ok": un envio
    "simulated" (NOTIFICATION_DRY_RUN=true, el default de la plataforma)
    es un resultado intencional, no un error de esta corrida -- se
    conserva el detalle completo (incluyendo si fue simulado) en
    run_scheduled_report, que es quien tiene el `results` original para
    armar el mensaje human-readable de last_status."""
    if not results:
        return "failed"
    if any(r.get("status") == "failed" for r in results):
        return "failed"
    return "ok"


async def run_scheduled_report(session_factory, schedule_id: str) -> None:
    """Llamado por el scheduler en proceso (APScheduler, ver app/main.py)
    cuando le toca disparar a una regla. No hay un usuario interactivo
    detras de un trigger programado, asi que se minta un token de
    servicio propio (mismo JWT_SECRET_KEY que comparten todos los
    microservicios via el .env comun) con rol admin y subject
    "system:report-scheduler", para poder llamar a los mismos endpoints
    autenticados que usaria un usuario (vuln-service/siem-service/
    case-service/purple-service). El reporte se genera igual que uno
    manual (generate_report), se exporta a PDF (export_to_pdf) y se
    manda por email como adjunto via notification-service -- si algo
    falla en el camino se registra el error en last_status y NO se
    tumba el scheduler."""
    async with session_factory() as db:
        schedule = await db.get(ReportSchedule, schedule_id)
        if schedule is None or not schedule.enabled:
            return
        report_type = schedule.report_type
        channel_id = schedule.notification_channel_id
        organization_id = schedule.organization_id or DEFAULT_ORGANIZATION_ID

    # org_id=organization_id es lo que faltaba antes de multi-tenancy: sin
    # esto, este token de servicio no llevaba tenant y cada servicio fuente
    # caia en la organizacion default sin importar de quien fuera la regla
    # de reporte programado.
    service_token = create_access_token("system:report-scheduler", "admin", org_id=organization_id)
    auth_header = f"Bearer {service_token}"
    status_note = "ok"
    try:
        async with session_factory() as db:
            report = await generate_report(db, report_type, auth_header, "scheduler:report-schedule", organization_id)
            await db.commit()
            stored_type = report.report_type
            stored_data = report.data

        pdf_bytes = export_to_pdf(stored_type, stored_data)
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        title = _REPORT_TITLES.get(stored_type, stored_type)
        filename = f"reporte_{stored_type}_{_now().strftime('%Y%m%d_%H%M')}.pdf"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{NOTIFICATION_SERVICE_URL}/notify",
                headers={"Authorization": auth_header},
                json={
                    "subject": f"SentinelOps - {title} ({_now().strftime('%Y-%m-%d')})",
                    "body": f"Reporte programado '{title}' generado automaticamente por SentinelOps. Se adjunta en PDF.",
                    "severity": "info",
                    "channel_ids": [channel_id],
                    "attachments": [
                        {
                            "filename": filename,
                            "content_type": "application/pdf",
                            "content_base64": pdf_b64,
                        }
                    ],
                },
                timeout=30.0,
            )
            response.raise_for_status()

        # notification-service devuelve 200 aunque no se haya enviado
        # nada de verdad (ej. `results: []` si el canal fue deshabilitado
        # o borrado despues de crear la regla, o un resultado por canal
        # con status "failed" si fallo el SMTP real) -- por eso hace falta
        # leer el body en vez de confiar solo en el status HTTP. Ver
        # summarize_notify_result.
        notify_results = response.json().get("results", [])
        if summarize_notify_result(notify_results) == "failed":
            if not notify_results:
                status_note = (
                    f"failed: notification-service no encontro ningun canal habilitado para "
                    f"channel_id={channel_id} (¿fue deshabilitado o borrado despues de crear la regla?)"
                )[:500]
            else:
                failed_detail = "; ".join(
                    f"{r.get('channel_type', '?')}: {r.get('error', 'sin detalle')}"
                    for r in notify_results
                    if r.get("status") == "failed"
                )
                status_note = f"failed: {failed_detail}"[:500]
        else:
            simulated = any(r.get("status") == "simulated" for r in notify_results)
            status_note = (
                "ok (simulado -- NOTIFICATION_DRY_RUN=true, no se mando ningun email real, ver docs/runbook.md)"
                if simulated
                else "ok"
            )
    except Exception as exc:  # noqa: BLE001 -- se registra el error, nunca tumba el scheduler
        logger.error("fallo al ejecutar reporte programado", extra={"schedule_id": schedule_id, "error": str(exc)})
        status_note = f"error: {exc}"[:500]

    async with session_factory() as db:
        schedule = await db.get(ReportSchedule, schedule_id)
        if schedule is not None:
            schedule.last_run_at = _now()
            schedule.last_status = status_note
            await db.commit()
