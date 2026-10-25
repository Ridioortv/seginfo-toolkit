"""Business logic for vuln-service: ingesta de hallazgos normalizados,
enriquecimiento (CVSS/EPSS/KEV), calculo de prioridad y workflow de triage
(confirmar / falso positivo / riesgo aceptado / remediado)."""
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import or_, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared import custody
from backend.shared.logging import configure_logging
from backend.shared.security import create_access_token
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.models import Vulnerability, VulnStatus, VulnSeverity
from app import closure, enrichment

logger = configure_logging("vuln-service")

ASSET_SERVICE_URL = os.getenv("ASSET_SERVICE_URL", "http://asset-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Limites de las columnas de la tabla `vulnerabilities` (ver models.py). En
# Postgres un valor mas largo que el VARCHAR hace fallar el INSERT con
# DataError -> 500 y se pierde TODO el lote de hallazgos (SQLite, el de los
# tests, no hace cumplir el largo, asi que sin esto el bug solo aparece en
# produccion). Ejemplo real: ZAP manda en `service` hasta 5 URLs juntas
# (varios cientos de caracteres) y la columna es String(100). Los escaneres
# son una fuente externa y no se les puede exigir que respeten estos
# largos, asi que se recorta aca, en el limite de confianza.
_MAX_TITLE = 500
_MAX_CVE_ID = 30
_MAX_PACKAGE = 255
_MAX_VERSION = 100
_MAX_SERVICE = 100
_MAX_SCANNER = 50


def _clip(value: str | None, limit: int) -> str:
    text = value or ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _clip_cve(value: str | None) -> str | None:
    if not value:
        return None
    return value[:_MAX_CVE_ID]


def _valid_port(value: int | None) -> int | None:
    return value if value is not None and 0 <= value <= 65535 else None


def _normalize_severity(value: str) -> VulnSeverity:
    try:
        return VulnSeverity(value)
    except ValueError:
        return VulnSeverity.info


async def _get_asset_criticality(asset_id: str | None, organization_id: str) -> str:
    """Best-effort: consulta asset-service por la criticidad del activo para
    ponderar el priority_score. Si el activo no existe o el servicio no
    responde, se asume criticidad 'medium' (no bloquea la ingesta).

    asset-service exige un JWT valido (get_current_claims) en GET
    /assets/{id} y ademas filtra por organization_id -- se emite un JWT de
    servicio-a-servicio de corta vida con el MISMO org_id que este hallazgo
    (no un token generico), para que la consulta caiga dentro del tenant
    correcto y nunca pueda leer un activo de otra organizacion."""
    if not asset_id:
        return "medium"
    token = create_access_token("system:vuln-service", "admin", org_id=organization_id)
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{ASSET_SERVICE_URL}/assets/{asset_id}", headers=headers)
            if resp.status_code == 200:
                return resp.json().get("criticality", "medium")
    except httpx.HTTPError as exc:
        logger.warning("no se pudo consultar asset-service", extra={"asset_id": asset_id, "error": str(exc)})
    return "medium"


async def ingest_findings(db: AsyncSession, payload, organization_id: str) -> tuple[int, int]:
    """Crea o actualiza registros de Vulnerability a partir de hallazgos de
    scan-service. Deduplica por (asset_id, cve_id o titulo) para no crear un
    registro nuevo por cada corrida de escaneo sobre el mismo activo, SIEMPRE
    dentro de la misma organizacion.

    `organization_id` lo resuelve el caller (main.py::ingest) desde el JWT
    YA VALIDADO de quien hace la llamada (org_id_from_claims) -- nunca
    desde un campo del body. Antes este endpoint aceptaba un
    "organization_id" en el propio payload sin ningun JWT que lo
    respaldara, asi que cualquiera que llegara a este puerto (publicado en
    docker-compose.yml) podia inyectar hallazgos falsos en CUALQUIER
    organizacion con solo adivinar/conocer su id."""
    created, updated = 0, 0
    asset_criticality = await _get_asset_criticality(payload.asset_id, organization_id)

    scanner = _clip(payload.scanner_type, _MAX_SCANNER)
    for finding in payload.findings:
        cve_id = _clip_cve(finding.cve_id)
        title = _clip(finding.title, _MAX_TITLE)
        existing = await _find_existing(db, organization_id, payload.asset_id, cve_id, title)
        if existing is not None:
            existing.scan_job_id = payload.scan_job_id or existing.scan_job_id
            existing.source_scanner = scanner or existing.source_scanner
            existing.description = finding.description or existing.description
            existing.updated_at = _now()
            updated += 1
            vuln = existing
        else:
            vuln = Vulnerability(
                organization_id=organization_id,
                cve_id=cve_id,
                title=title,
                description=finding.description,
                severity=_normalize_severity(finding.severity),
                source_scanner=scanner,
                scan_job_id=payload.scan_job_id,
                asset_id=payload.asset_id,
                package=_clip(finding.package, _MAX_PACKAGE),
                installed_version=_clip(finding.installed_version, _MAX_VERSION),
                fixed_version=_clip(finding.fixed_version, _MAX_VERSION),
                port=_valid_port(finding.port),
                service=_clip(finding.service, _MAX_SERVICE),
            )
            db.add(vuln)
            await db.flush()
            created += 1

        if cve_id:
            await _enrich(vuln, asset_criticality)
        else:
            vuln.priority_score = enrichment.compute_priority_score(None, None, False, asset_criticality)

    await db.flush()
    return created, updated


async def _find_existing(
    db: AsyncSession, organization_id: str, asset_id: str | None, cve_id: str | None, title: str
) -> Vulnerability | None:
    # Una vulnerabilidad "remediada" no se reutiliza, salvo mientras se verifica su cierre: el re-escaneo que
    # la comprueba tambien la ingesta, y no debe crear un duplicado (closure.step la reabre si sigue ahi).
    query = select(Vulnerability).where(
        Vulnerability.organization_id == organization_id,
        or_(Vulnerability.status != VulnStatus.remediated, Vulnerability.closure_status == "pending"),
    )
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.where(Vulnerability.cve_id == cve_id)
    else:
        query = query.where(Vulnerability.cve_id.is_(None), Vulnerability.title == title)
    result = await db.execute(query.limit(1))
    return result.scalar_one_or_none()


async def _enrich(vuln: Vulnerability, asset_criticality: str) -> None:
    cvss_score, cvss_vector = await enrichment.fetch_cvss(vuln.cve_id)
    epss_score = await enrichment.fetch_epss(vuln.cve_id)
    is_kev, kev_date = await enrichment.check_kev(vuln.cve_id)

    vuln.cvss_score = cvss_score if cvss_score is not None else vuln.cvss_score
    vuln.cvss_vector = cvss_vector or vuln.cvss_vector
    vuln.epss_score = epss_score if epss_score is not None else vuln.epss_score
    vuln.is_kev = is_kev or vuln.is_kev
    vuln.kev_date_added = kev_date or vuln.kev_date_added
    vuln.priority_score = enrichment.compute_priority_score(vuln.cvss_score, vuln.epss_score, vuln.is_kev, asset_criticality)
    vuln.last_enriched_at = _now()


async def reenrich_vulnerability(db: AsyncSession, vuln: Vulnerability) -> Vulnerability:
    if vuln.cve_id:
        organization_id = vuln.organization_id or DEFAULT_ORGANIZATION_ID
        asset_criticality = await _get_asset_criticality(vuln.asset_id, organization_id)
        await _enrich(vuln, asset_criticality)
        await db.flush()
    return vuln


async def list_vulnerabilities(
    db: AsyncSession,
    organization_id: str,
    status_filter: str | None = None,
    severity: str | None = None,
    asset_id: str | None = None,
    min_priority: float | None = None,
    scan_job_id: str | None = None,
    closure_status: str | None = None,
) -> list[Vulnerability]:
    query = select(Vulnerability).where(Vulnerability.organization_id == organization_id)
    if status_filter:
        query = query.where(Vulnerability.status == status_filter)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if min_priority is not None:
        query = query.where(Vulnerability.priority_score >= min_priority)
    if closure_status:
        query = query.where(Vulnerability.closure_status == closure_status)
    if scan_job_id:
        # Usado por la pagina de Escaneos para mostrar los resultados
        # enriquecidos (severidad/CVSS/EPSS/remediacion) de UN escaneo
        # puntual. OJO: si el mismo activo se volvio a escanear despues,
        # ingest_findings reasigna scan_job_id al escaneo MAS RECIENTE que
        # toco cada fila (ver ese metodo) -- este filtro muestra el estado
        # actual de esas vulnerabilidades, que puede no coincidir 1 a 1 con
        # los hallazgos crudos de un escaneo viejo si hubo un rescan.
        query = query.where(Vulnerability.scan_job_id == scan_job_id)
    result = await db.execute(query.order_by(Vulnerability.priority_score.desc(), Vulnerability.created_at.desc()))
    return list(result.scalars().all())


async def get_vulnerability(db: AsyncSession, vuln_id: str, organization_id: str) -> Vulnerability | None:
    vuln = await db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.organization_id != organization_id:
        return None
    return vuln


async def triage_vulnerability(db: AsyncSession, vuln: Vulnerability, payload, actor: str) -> Vulnerability:
    previous_status = getattr(vuln.status, "value", vuln.status)
    if payload.status == VulnStatus.remediated and previous_status != "remediated":
        closure.mark_remediated(vuln)
    elif payload.status != VulnStatus.remediated and previous_status == "remediated":
        closure.clear_closure(vuln)
    vuln.status = payload.status
    vuln.triage_note = payload.note
    vuln.triaged_by = actor
    vuln.updated_at = _now()
    await db.flush()
    await db.refresh(vuln)
    await custody.record_event(
        "vuln.status_changed", service="vuln-service", organization_id=vuln.organization_id, actor=actor,
        subject_type="vuln", subject_id=vuln.id,
        refs=[f"vuln:{vuln.id}"] + ([f"asset:{vuln.asset_id}"] if vuln.asset_id else []),
        payload={"title": vuln.title, "cve": vuln.cve_id or "", "severity": getattr(vuln.severity, "value", vuln.severity),
                 "from": previous_status, "to": getattr(vuln.status, "value", vuln.status),
                 "note": (vuln.triage_note or "")[:500]},
    )
    return vuln


async def delete_vulnerability(db: AsyncSession, vuln: Vulnerability) -> None:
    """Borra UNA vulnerabilidad (la que el usuario eligio en la tabla). Ojo: si
    el mismo hallazgo vuelve a aparecer en un escaneo futuro, la ingesta lo
    crea de nuevo -- para que deje de molestar sin borrarlo, se lo marca como
    "falso positivo" o "riesgo aceptado" (triage)."""
    await db.delete(vuln)
    await db.flush()


async def get_stats(db: AsyncSession, organization_id: str) -> dict:
    total_result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.organization_id == organization_id)
    )
    total = total_result.scalar_one()

    by_status = dict(
        (row[0].value, row[1])
        for row in (await db.execute(
            select(Vulnerability.status, func.count(Vulnerability.id))
            .where(Vulnerability.organization_id == organization_id)
            .group_by(Vulnerability.status)
        )).all()
    )
    by_severity = dict(
        (row[0].value, row[1])
        for row in (await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.organization_id == organization_id)
            .group_by(Vulnerability.severity)
        )).all()
    )
    kev_result = await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.organization_id == organization_id, Vulnerability.is_kev.is_(True)
        )
    )
    kev_count = kev_result.scalar_one()

    avg_result = await db.execute(
        select(func.avg(Vulnerability.priority_score)).where(Vulnerability.organization_id == organization_id)
    )
    avg_priority = avg_result.scalar_one() or 0.0

    return {
        "total": total,
        "by_status": by_status,
        "by_severity": by_severity,
        "kev_count": kev_count,
        "avg_priority_score": round(float(avg_priority), 2),
    }


async def get_posture(db: AsyncSession, organization_id: str) -> dict:
    """Lo abierto hoy, para el panel de cumplimiento: por severidad, explotadas activamente (KEV) y la mas vieja."""
    rows = (await db.execute(
        select(Vulnerability.severity, Vulnerability.is_kev, Vulnerability.created_at).where(
            Vulnerability.organization_id == organization_id, Vulnerability.status.in_([VulnStatus.open, VulnStatus.confirmed])
        )
    )).all()
    now = datetime.now(timezone.utc)
    by_sev: dict[str, int] = {}
    kev_open = 0
    oldest = {"critical": 0.0, "high": 0.0}
    for sev, kev, created in rows:
        key = getattr(sev, "value", sev)
        by_sev[key] = by_sev.get(key, 0) + 1
        kev_open += 1 if kev else 0
        if key in oldest and created is not None:
            c = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            oldest[key] = max(oldest[key], round((now - c).total_seconds() / 86400, 1))
    return {"open_total": len(rows), "open_by_severity": by_sev, "open_kev": kev_open,
            "oldest_open_days": oldest}
