"""Business logic for vuln-service: ingesta de hallazgos normalizados,
enriquecimiento (CVSS/EPSS/KEV), calculo de prioridad y workflow de triage
(confirmar / falso positivo / riesgo aceptado / remediado)."""
import os
from datetime import datetime, timedelta, timezone
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


def accept_risk_needs_exception(vuln: Vulnerability) -> bool:
    """Aceptar el riesgo de una vulnerabilidad ALTA o CRITICA no es una decision de una sola persona con un clic: exige una
    excepcion aprobada (case-service, Confianza y evidencia -> Excepciones), con justificacion, controles compensatorios,
    otra persona que apruebe y vencimiento. VULN_ACCEPT_RISK_REQUIRES_EXCEPTION=false lo desactiva (instalaciones de una
    sola persona). Reafirmar un riesgo ya aceptado no cambia el estado y no pide excepcion."""
    if os.getenv("VULN_ACCEPT_RISK_REQUIRES_EXCEPTION", "true").strip().lower() in ("0", "false", "no"):
        return False
    severity = getattr(vuln.severity, "value", vuln.severity)
    status_ = getattr(vuln.status, "value", vuln.status)
    return severity in ("critical", "high") and status_ != "accepted_risk"


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


EXPOSURE_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


async def get_executive(db: AsyncSession, organization_id: str, days: int = 30, now: datetime | None = None) -> dict:
    """Numeros para el tablero ejecutivo: lo abierto hoy, el flujo del periodo (nuevas y remediadas) contra el periodo
    anterior de la misma duracion, y la exposicion por activo. Todo sale de las marcas de tiempo reales de cada
    vulnerabilidad (created_at / remediated_at); no hay estimaciones."""
    now = now or datetime.now(timezone.utc)
    days = max(7, min(int(days), 365))
    cur_start, prev_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    rows = (await db.execute(select(Vulnerability).where(Vulnerability.organization_id == organization_id))).scalars().all()

    def sev(v) -> str:
        return getattr(v.severity, "value", v.severity)

    def stat(v) -> str:
        return getattr(v.status, "value", v.status)

    open_rows = [v for v in rows if stat(v) in ("open", "confirmed")]
    by_sev: dict[str, int] = {}
    for v in open_rows:
        by_sev[sev(v)] = by_sev.get(sev(v), 0) + 1

    def window(lo: datetime, hi: datetime) -> dict:
        created = [v for v in rows if (c := _aware(v.created_at)) and lo <= c < hi]
        fixed = [v for v in rows if stat(v) == "remediated" and (r := _aware(v.remediated_at)) and lo <= r < hi]
        ch = ("critical", "high")
        return {"created": len(created), "remediated": len(fixed),
                "created_critical_high": sum(1 for v in created if sev(v) in ch),
                "remediated_critical_high": sum(1 for v in fixed if sev(v) in ch)}

    assets: dict[str, dict] = {}
    for v in open_rows:
        key = v.asset_id or ""
        a = assets.setdefault(key, {"asset_id": key, "critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0, "score": 0.0})
        if sev(v) in a:
            a[sev(v)] += 1
        a["kev"] += 1 if v.is_kev else 0
        a["score"] += EXPOSURE_WEIGHTS.get(sev(v), 0.0) * (1.5 if v.is_kev else 1.0)
    top = sorted(assets.values(), key=lambda a: -a["score"])[:200]
    for a in top:
        a["score"] = round(a["score"], 1)
    oldest = max(((now - c).days for v in open_rows if sev(v) in ("critical", "high") and (c := _aware(v.created_at))), default=0)
    return {
        "days": days, "generated_at": now.isoformat(),
        "open": {"total": len(open_rows), "by_severity": by_sev, "kev": sum(1 for v in open_rows if v.is_kev),
                 "critical_high": by_sev.get("critical", 0) + by_sev.get("high", 0), "oldest_critical_high_days": oldest,
                 "accepted_risk": sum(1 for v in rows if stat(v) == "accepted_risk")},
        "period": window(cur_start, now), "previous": window(prev_start, cur_start),
        "exposure_weights": EXPOSURE_WEIGHTS, "by_asset": top,
    }
