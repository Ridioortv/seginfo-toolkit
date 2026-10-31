"""Tickets vinculados (Jira / ServiceNow) en los dos sentidos.

IDA: desde una vulnerabilidad o un caso se crea el ticket en el sistema de la empresa (con titulo, severidad, CVE, activo y
pasos sugeridos) y se guarda el vinculo.

VUELTA: cuando el ticket se resuelve en el sistema externo, TERO se entera de dos maneras: el sistema externo avisa por un
webhook, o TERO pregunta cada TICKET_SYNC_SECONDS (300 por defecto; 0 lo apaga). En los dos casos TERO NO se fia del aviso:
vuelve a consultar el estado del ticket al sistema externo con las credenciales del conector. Recien ahi:
  * vulnerabilidad: pasa a "remediada" y arranca la verificacion con un nuevo escaneo (que el ticket diga "Hecho" no la da por
    corregida; el cierre verificado la confirma o la reabre);
  * caso: pasa a "resuelto" con una nota en su historial;
  * si el ticket se cerro como "no se hara" / duplicado / cancelado, NO se toca la vulnerabilidad: queda abierta y el vinculo
    lo marca. Aceptar el riesgo exige una excepcion aprobada.
Cada hecho queda en la cadena de custodia (ticket.created, ticket.resolved, ticket.closed_no_fix)."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody
from backend.shared.logging import configure_logging
from backend.shared.service_auth import service_auth_headers
from app import ticket_providers as providers
from app.models import Connector, TicketLog
from app.ticket_models import TicketLink

logger = configure_logging("integration-service")
SERVICE = "integration-service"
URLS = {"vuln": os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000"),
        "case": os.getenv("CASE_SERVICE_URL", "http://case-service:8000"),
        "notify": os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8000")}
SYNC_SECONDS = int(os.getenv("TICKET_SYNC_SECONDS", "300"))
SUBJECT_TYPES = ("vulnerability", "case")
ACTIVE_STATES = ("open", "simulated")
SEVERITY_LABEL = {"critical": "Critica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa"}
WEBHOOK_KEY = "_webhook_sha256"


class TicketError(Exception):
    def __init__(self, message: str, status: int = 422, extra: dict | None = None):
        super().__init__(message)
        self.status, self.extra = status, extra or {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dry() -> bool:
    return os.getenv("INTEGRATION_DRY_RUN", "true").lower() != "false"


# ----------------------------- secreto del webhook entrante -----------------------------

def new_webhook_secret(connector: Connector) -> str:
    """Genera un secreto nuevo (256 bits), guarda SOLO su hash en el conector y devuelve el secreto una unica vez."""
    token = secrets.token_urlsafe(32)
    connector.config = {**(connector.config or {}), WEBHOOK_KEY: hashlib.sha256(token.encode()).hexdigest()}
    return token


def webhook_secret_ok(connector: Connector, token: str) -> bool:
    stored = (connector.config or {}).get(WEBHOOK_KEY, "")
    return bool(stored) and hmac.compare_digest(stored, hashlib.sha256(token.encode()).hexdigest())


# ----------------------------- datos de lo que se vincula -----------------------------

async def _service_get(url: str, org: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers=service_auth_headers(SERVICE, org))
    except httpx.HTTPError:
        raise TicketError("No pude consultar los datos (servicio no disponible). Proba de nuevo en un momento.", 502)
    if resp.status_code == 404:
        raise TicketError("No se encontro lo que queres vincular", 404)
    if resp.status_code >= 300:
        raise TicketError(f"No pude consultar los datos (HTTP {resp.status_code})", 502)
    return resp.json()


def build_vulnerability_ticket(v: dict) -> tuple[str, str, str]:
    sev = v.get("severity", "medium")
    title = f"[TERO][{SEVERITY_LABEL.get(sev, sev)}] {v.get('title', 'Vulnerabilidad')}"
    lines = [f"Vulnerabilidad detectada por TERO Security.", "",
             f"Severidad: {SEVERITY_LABEL.get(sev, sev)}" + (" - EXPLOTADA ACTIVAMENTE (lista KEV)" if v.get("is_kev") else "")]
    if v.get("cve_id"):
        lines.append(f"CVE: {v['cve_id']}")
    if v.get("cvss_score") is not None:
        lines.append(f"CVSS: {v['cvss_score']}")
    where = ", ".join(x for x in (f"puerto {v['port']}" if v.get("port") else "", v.get("service", ""), v.get("package", "")) if x)
    if where:
        lines.append(f"Donde: {where}")
    if v.get("installed_version") or v.get("fixed_version"):
        lines.append(f"Version instalada: {v.get('installed_version') or '-'} | corregida en: {v.get('fixed_version') or '-'}")
    if v.get("description"):
        lines += ["", v["description"][:1500]]
    if v.get("remediation_steps"):
        lines += ["", "Pasos sugeridos:"] + [f"- {s}" for s in v["remediation_steps"][:6]]
    lines += ["", "Al resolver este ticket, TERO volvera a escanear para comprobar que la vulnerabilidad se corrigio de verdad."]
    return title[:250], "\n".join(lines), sev if sev in ("critical", "high", "medium", "low") else "medium"


def build_case_ticket(c: dict) -> tuple[str, str, str]:
    pr = c.get("priority", "medium")
    title = f"[TERO][caso] {c.get('title', 'Caso')}"
    lines = ["Caso de respuesta a incidentes abierto en TERO Security.", "", f"Prioridad: {pr}"]
    if c.get("description"):
        lines += ["", str(c["description"])[:2000]]
    return title[:250], "\n".join(lines), pr if pr in ("critical", "high", "medium", "low") else "medium"


async def fetch_subject(org: str, subject_type: str, subject_id: str) -> tuple[dict, tuple[str, str, str]]:
    if subject_type == "vulnerability":
        v = await _service_get(f"{URLS['vuln']}/internal/vulnerabilities/{subject_id}", org)
        if v.get("status") not in ("open", "confirmed"):
            raise TicketError("Solo se abre un ticket para una vulnerabilidad abierta o confirmada", 409)
        return v, build_vulnerability_ticket(v)
    c = await _service_get(f"{URLS['case']}/cases/{subject_id}", org)
    if c.get("status") in ("resolved", "closed"):
        raise TicketError("Este caso ya esta resuelto", 409)
    return c, build_case_ticket(c)


# ----------------------------- crear -----------------------------

async def pick_connector(db: AsyncSession, org: str, connector_id: str | None) -> Connector:
    q = select(Connector).where(Connector.organization_id == org, Connector.kind == "ticketing", Connector.enabled == True)  # noqa: E712
    if connector_id:
        q = q.where(Connector.id == connector_id)
    row = (await db.execute(q.order_by(Connector.created_at.desc()))).scalars().first()
    if row is None:
        raise TicketError("No hay un conector de tickets habilitado. Configuralo en Integraciones.", 409)
    return row


async def active_link(db: AsyncSession, org: str, subject_type: str, subject_id: str, connector_id: str) -> TicketLink | None:
    return (await db.execute(select(TicketLink).where(
        TicketLink.organization_id == org, TicketLink.subject_type == subject_type, TicketLink.subject_id == subject_id,
        TicketLink.connector_id == connector_id, TicketLink.state.in_(ACTIVE_STATES)))).scalars().first()


async def _custody(event: str, link: TicketLink, actor: str, **payload) -> None:
    await custody.record_event(
        event, service=SERVICE, organization_id=link.organization_id, actor=actor, subject_type=link.subject_type,
        subject_id=link.subject_id, refs=[f"{'vuln' if link.subject_type == 'vulnerability' else 'case'}:{link.subject_id}"],
        payload={"ticket": link.external_key, "provider": link.provider, "link_id": link.id, **payload})


async def notify_chat(connector: Connector, subject: str, body: str, severity: str) -> None:
    """Avisa por los canales (Slack/Teams/mail) que el conector tenga elegidos. Sin elegir, no avisa a nadie."""
    ids = [i for i in (connector.config or {}).get("notify_channel_ids", []) if isinstance(i, str)]
    if not ids:
        return
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            await client.post(f"{URLS['notify']}/internal/notify", headers=service_auth_headers(SERVICE, connector.organization_id),
                              json={"subject": subject[:200], "body": body[:1500], "severity": severity, "channel_ids": ids})
    except httpx.HTTPError:
        logger.warning("no se pudo avisar al chat del ticket")


async def create_for_subject(db: AsyncSession, org: str, actor: str, subject_type: str, subject_id: str,
                             connector_id: str | None = None) -> TicketLink:
    if subject_type not in SUBJECT_TYPES:
        raise TicketError("Tipo de elemento no valido", 422)
    connector = await pick_connector(db, org, connector_id)
    existing = await active_link(db, org, subject_type, subject_id, connector.id)
    if existing is not None:
        raise TicketError("Ya hay un ticket abierto para esto", 409, {"link_id": existing.id, "external_key": existing.external_key})
    subject, (title, description, priority) = await fetch_subject(org, subject_type, subject_id)
    link = TicketLink(organization_id=org, connector_id=connector.id, provider=providers.provider_of(connector.config),
                      subject_type=subject_type, subject_id=subject_id, subject_title=subject.get("title", "")[:500], created_by=actor[:255])
    if _dry():
        link.state, link.last_error = "simulated", "Simulado: INTEGRATION_DRY_RUN=true. No se llamo al sistema de tickets."
        status_, key, url = "simulated", "", ""
    else:
        try:
            created = await providers.create(_decrypted(connector), title, description, priority)
        except providers.ProviderError as exc:
            db.add(TicketLog(organization_id=org, connector_id=connector.id, title=title, priority=priority, status="failed", error=str(exc)))
            await db.commit()  # el intento fallido queda en el historial aunque no haya vinculo
            raise TicketError(str(exc), 502)
        link.external_key, link.external_id, link.external_url, link.state = created.key, created.external_id, created.url, "open"
        status_, key, url = "executed", created.key, created.url
    db.add(link)
    db.add(TicketLog(organization_id=org, connector_id=connector.id, title=title, priority=priority, status=status_,
                     external_key=key, external_url=url))
    await db.flush()
    if link.state == "open":
        await _custody("ticket.created", link, actor, subject_title=link.subject_title[:200], priority=priority)
        await notify_chat(connector, f"Ticket {link.external_key} creado",
                          f"{title}\n{link.external_url}", "high" if priority in ("critical", "high") else "medium")
    return link


def _decrypted(connector: Connector) -> dict:
    """La config tal cual (los secretos siguen cifrados: ticket_providers los descifra justo al usarlos)."""
    return dict(connector.config or {})


# ----------------------------- la vuelta -----------------------------

async def _apply_vulnerability(link: TicketLink) -> str:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{URLS['vuln']}/internal/vulnerabilities/{link.subject_id}/ticket-resolved",
                                     headers=service_auth_headers(SERVICE, link.organization_id),
                                     json={"ticket_key": link.external_key, "provider": link.provider,
                                           "actor": f"ticket:{link.external_key}"})
    except httpx.HTTPError:
        raise TicketError("No pude avisarle a vuln-service; se reintenta en el proximo ciclo", 502)
    if resp.status_code == 404:
        return "La vulnerabilidad ya no existe"
    if resp.status_code >= 300:
        raise TicketError(f"vuln-service respondio HTTP {resp.status_code}; se reintenta en el proximo ciclo", 502)
    data = resp.json()
    if data.get("changed"):
        return "Vulnerabilidad marcada como remediada; arranco la verificacion con un nuevo escaneo"
    return f"La vulnerabilidad ya estaba en estado {data.get('status')}: no se cambio nada"


async def _apply_case(link: TicketLink) -> str:
    headers = service_auth_headers(SERVICE, link.organization_id)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            got = await client.get(f"{URLS['case']}/cases/{link.subject_id}", headers=headers)
            if got.status_code == 404:
                return "El caso ya no existe"
            got.raise_for_status()
            status_ = got.json().get("status")
            if status_ in ("resolved", "closed"):
                return f"El caso ya estaba {status_}: no se cambio nada"
            if status_ == "open":
                (await client.patch(f"{URLS['case']}/cases/{link.subject_id}", headers=headers, json={"status": "in_progress"})).raise_for_status()
            (await client.patch(f"{URLS['case']}/cases/{link.subject_id}", headers=headers, json={"status": "resolved"})).raise_for_status()
            await client.post(f"{URLS['case']}/cases/{link.subject_id}/timeline", headers=headers,
                              json={"action": "ticket_resuelto", "notes": f"El ticket {link.external_key} ({link.provider}) se resolvio."})
    except httpx.HTTPError:
        raise TicketError("No pude actualizar el caso; se reintenta en el proximo ciclo", 502)
    return "Caso marcado como resuelto"


async def sync_link(db: AsyncSession, link: TicketLink, connector: Connector | None = None) -> TicketLink:
    """Pregunta al sistema externo por el estado y aplica el cierre una sola vez. Nunca levanta: deja el error en el vinculo."""
    if link.state not in ("open", "resolved") or not link.external_key:
        return link
    connector = connector or await db.get(Connector, link.connector_id)
    now = _now()
    if connector is None or not connector.enabled:
        link.last_error, link.last_synced_at = "El conector ya no existe o esta deshabilitado", now
        return link
    try:
        st = await providers.fetch_status(_decrypted(connector), link.external_key, link.external_id)
    except providers.ProviderError as exc:
        link.last_error, link.last_synced_at = str(exc), now
        return link
    link.external_status, link.last_synced_at, link.last_error, link.updated_at = st.raw[:100], now, "", now
    if st.state == "open":
        if link.state == "resolved":  # lo reabrieron afuera
            link.state, link.applied = "open", False
        return link
    if st.state == "canceled":
        if link.state != "closed_no_fix":
            link.state, link.resolved_at = "closed_no_fix", now
            link.applied_note = "El ticket se cerro sin corregir (cancelado, duplicado o 'no se hara'). La vulnerabilidad sigue abierta."
            await _custody("ticket.closed_no_fix", link, f"ticket:{link.external_key}", external_status=st.raw)
            await notify_chat(connector, f"Ticket {link.external_key} cerrado sin corregir", link.applied_note, "medium")
        return link
    # resolved
    link.state = "resolved"
    link.resolved_at = link.resolved_at or now
    if not link.applied:
        try:
            note = await (_apply_vulnerability(link) if link.subject_type == "vulnerability" else _apply_case(link))
        except TicketError as exc:
            link.last_error = str(exc)
            return link
        link.applied, link.applied_note = True, note
        await _custody("ticket.resolved", link, f"ticket:{link.external_key}", external_status=st.raw, effect=note)
        await notify_chat(connector, f"Ticket {link.external_key} resuelto", f"{link.subject_title}\n{note}", "medium")
    return link


def extract_refs(payload: dict) -> list[str]:
    """Identificadores del ticket que pueden venir en el aviso: Jira (issue.key / issue.id), ServiceNow (number / sys_id) o genericos."""
    out: list[str] = []
    issue = payload.get("issue") if isinstance(payload.get("issue"), dict) else {}
    for v in (issue.get("key"), issue.get("id"), payload.get("number"), payload.get("sys_id"), payload.get("key"),
              payload.get("external_key"), payload.get("id")):
        if isinstance(v, (str, int)) and str(v).strip() and len(str(v)) <= 100:
            out.append(str(v).strip())
    return out


async def handle_webhook(db: AsyncSession, connector: Connector, payload: dict) -> dict:
    """El aviso solo dice QUE ticket cambio: el estado se vuelve a pedir al sistema externo (no se confia en el contenido)."""
    refs = extract_refs(payload if isinstance(payload, dict) else {})
    if not refs:
        return {"matched": 0, "synced": 0}
    links = (await db.execute(select(TicketLink).where(
        TicketLink.organization_id == connector.organization_id, TicketLink.connector_id == connector.id,
        (TicketLink.external_key.in_(refs)) | (TicketLink.external_id.in_(refs))))).scalars().all()
    for link in links:
        await sync_link(db, link, connector)
    return {"matched": len(links), "synced": len(links)}


async def sync_open(db: AsyncSession, org: str | None = None) -> dict:
    # abiertos, y resueltos cuyo cierre todavia no se pudo aplicar del lado de TERO (se reintenta)
    q = select(TicketLink).where(((TicketLink.state == "open") | ((TicketLink.state == "resolved") & (TicketLink.applied.is_(False)))),
                                 TicketLink.external_key != "")
    if org:
        q = q.where(TicketLink.organization_id == org)
    links = (await db.execute(q)).scalars().all()
    resolved = 0
    for link in links:
        before = (link.state, link.applied)
        await sync_link(db, link)
        resolved += 1 if (link.state, link.applied) != before else 0
    return {"checked": len(links), "changed": resolved}


async def loop(session_factory) -> None:
    if SYNC_SECONDS <= 0:
        return
    await asyncio.sleep(60)
    while True:
        try:
            if not _dry():
                async with session_factory() as db:
                    await sync_open(db)
                    await db.commit()
        except Exception as exc:
            logger.warning("fallo la sincronizacion de tickets", extra={"error": str(exc)})
        await asyncio.sleep(max(60, SYNC_SECONDS))


async def list_links(db: AsyncSession, org: str, subject_type: str | None = None, subject_id: str | None = None,
                     state: str | None = None, limit: int = 200) -> list[TicketLink]:
    q = select(TicketLink).where(TicketLink.organization_id == org)
    if subject_type:
        q = q.where(TicketLink.subject_type == subject_type)
    if subject_id:
        q = q.where(TicketLink.subject_id == subject_id)
    if state:
        q = q.where(TicketLink.state == state)
    return list((await db.execute(q.order_by(TicketLink.created_at.desc()).limit(limit))).scalars().all())


def view(l: TicketLink, connector_name: str = "") -> dict:
    def iso(d):
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat() if d else None
    return {"id": l.id, "connector_id": l.connector_id, "connector_name": connector_name, "provider": l.provider,
            "subject_type": l.subject_type, "subject_id": l.subject_id, "subject_title": l.subject_title,
            "external_key": l.external_key, "external_url": l.external_url, "state": l.state,
            "external_status": l.external_status, "applied": l.applied, "applied_note": l.applied_note,
            "last_error": l.last_error, "created_by": l.created_by, "created_at": iso(l.created_at),
            "last_synced_at": iso(l.last_synced_at), "resolved_at": iso(l.resolved_at)}
