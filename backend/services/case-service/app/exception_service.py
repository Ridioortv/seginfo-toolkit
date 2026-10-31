"""Logica de las excepciones de riesgo.

Regla de fondo: aceptar el riesgo de una vulnerabilidad alta o critica no lo decide una sola persona con un clic.
  * Pide una persona (analista o mas): justificacion, controles compensatorios y por cuantos dias.
  * Aprueba OTRA persona (admin o soc_manager; si la vulnerabilidad es critica, solo admin). En una instalacion de una
    sola persona se puede permitir la auto-aprobacion con RISK_EXCEPTION_ALLOW_SELF_APPROVAL=true (queda anotada).
  * Al aprobar, vuln-service pasa la vulnerabilidad a "riesgo aceptado"; al vencer o revocarse, la reabre sola.
  * Todo queda en la cadena de custodia y se puede bajar una prueba firmada de cada excepcion."""
from __future__ import annotations

import asyncio
import csv
import io
import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from backend.shared.logging import configure_logging
from backend.shared.service_auth import service_auth_headers
from app import custody_service as custody
from app.exception_models import RiskException

logger = configure_logging("risk-exceptions")
VULN_URL = os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000")
CHECK_EVERY_SECONDS = int(os.getenv("RISK_EXCEPTION_CHECK_SECONDS", "900"))
MIN_DAYS = 7
MAX_DAYS = {"critical": 90, "high": 180}
DEFAULT_MAX_DAYS = 365
EXPIRING_SOON_DAYS = 14
ACTIVE = ("approved",)
FINISHED = ("rejected", "withdrawn", "revoked", "expired", "closed")
STATUS_LABEL = {"pending": "Pendiente de aprobacion", "approved": "Vigente", "rejected": "Rechazada", "withdrawn": "Retirada",
                "revoked": "Revocada", "expired": "Vencida", "closed": "Cerrada"}


class ExceptionError(Exception):
    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _iso(dt: datetime | None) -> str | None:
    dt = _aware(dt)
    return dt.isoformat() if dt else None


def allow_self_approval() -> bool:
    return os.getenv("RISK_EXCEPTION_ALLOW_SELF_APPROVAL", "false").strip().lower() in ("1", "true", "yes")


def max_days_for(severity: str) -> int:
    return MAX_DAYS.get(severity, DEFAULT_MAX_DAYS)


# ----------------------------- cliente de vuln-service -----------------------------

async def fetch_vulnerability(org_id: str | None, vuln_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{VULN_URL}/internal/vulnerabilities/{vuln_id}", headers=service_auth_headers("case-service", org_id))
    except httpx.HTTPError:
        raise ExceptionError("No pude consultar vuln-service. Proba de nuevo en un momento.", 502)
    if resp.status_code == 404:
        raise ExceptionError("Vulnerabilidad no encontrada", 404)
    if resp.status_code >= 400:
        raise ExceptionError("vuln-service no pudo responder la consulta", 502)
    return resp.json()


async def set_acceptance(org_id: str | None, vuln_id: str, action: str, note: str, actor: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{VULN_URL}/internal/vulnerabilities/{vuln_id}/risk-acceptance",
                json={"action": action, "note": note[:1000], "actor": actor},
                headers=service_auth_headers("case-service", org_id))
    except httpx.HTTPError:
        raise ExceptionError("No pude comunicarme con vuln-service; no se cambio nada. Proba de nuevo en un momento.", 502)
    if resp.status_code == 409:
        raise ExceptionError(resp.json().get("detail", "La vulnerabilidad cambio de estado"), 409)
    if resp.status_code == 404:
        raise ExceptionError("La vulnerabilidad ya no existe", 404)
    if resp.status_code >= 400:
        raise ExceptionError("vuln-service rechazo el cambio", 502)


# ----------------------------- operaciones -----------------------------

async def get(db: AsyncSession, org_id: str | None, exception_id: str) -> RiskException | None:
    return (await db.execute(select(RiskException).where(
        RiskException.id == exception_id, RiskException.organization_id == org_id))).scalars().first()


async def _log(db: AsyncSession, org_id: str | None, event: str, actor: str, row: RiskException, **extra) -> None:
    await custody.append(
        db, org_id, f"risk_exception.{event}", actor=actor, source="case-service", subject_type="risk_exception",
        subject_id=row.id, refs=[f"vuln:{row.vuln_id}"],
        payload={"vuln_id": row.vuln_id, "title": row.vuln_title, "severity": row.vuln_severity, "cve": row.cve_id,
                 "status": row.status, "justification_sha256": core.sha256_hex(row.justification), **extra})


def _clean_text(value: str, minimum: int, label: str, limit: int = 3000) -> str:
    v = (value or "").strip()
    if len(v) < minimum:
        raise ExceptionError(f"{label}: escribi al menos {minimum} caracteres")
    return v[:limit]


async def request(db: AsyncSession, org_id: str | None, actor: str, vuln_id: str, justification: str,
                  compensating_controls: str, days: int) -> RiskException:
    vuln = await fetch_vulnerability(org_id, vuln_id)
    if vuln["status"] not in ("open", "confirmed"):
        raise ExceptionError(f"La vulnerabilidad esta en estado {vuln['status']}: solo se pide excepcion para una abierta o confirmada", 409)
    justification = _clean_text(justification, 30, "La justificacion")
    severity = vuln["severity"]
    needs_controls = severity in ("critical", "high")
    controls = (compensating_controls or "").strip()
    if needs_controls:
        controls = _clean_text(controls, 20, "Los controles compensatorios (obligatorios en altas y criticas)")
    limit = max_days_for(severity)
    if not (MIN_DAYS <= int(days) <= limit):
        raise ExceptionError(f"Para una vulnerabilidad {severity} la excepcion puede durar entre {MIN_DAYS} y {limit} dias")
    open_ones = (await db.execute(select(RiskException).where(
        RiskException.organization_id == org_id, RiskException.vuln_id == vuln_id,
        RiskException.status.in_(("pending", "approved"))))).scalars().all()
    if open_ones:
        raise ExceptionError("Esta vulnerabilidad ya tiene una excepcion pendiente o vigente", 409)
    row = RiskException(
        organization_id=org_id, vuln_id=vuln_id, vuln_title=vuln["title"][:500], vuln_severity=severity, cve_id=vuln.get("cve_id", "")[:30],
        justification=justification, compensating_controls=controls[:3000], requested_days=int(days), requested_by=actor[:255])
    db.add(row)
    await db.flush()
    await _log(db, org_id, "requested", actor, row, requested_days=row.requested_days)
    return row


def check_can_approve(row: RiskException, role: str, actor: str) -> None:
    if row.status != "pending":
        raise ExceptionError("Solo se decide una excepcion pendiente", 409)
    if row.vuln_severity == "critical" and role != "admin":
        raise ExceptionError("Una vulnerabilidad critica solo la puede aprobar un administrador", 403)
    if actor.strip().lower() == row.requested_by.strip().lower() and not allow_self_approval():
        raise ExceptionError("No podes aprobar tu propia excepcion: tiene que aprobarla otra persona", 403)


async def approve(db: AsyncSession, org_id: str | None, actor: str, role: str, row: RiskException, note: str) -> RiskException:
    check_can_approve(row, role, actor)
    note = _clean_text(note, 10, "El motivo de la aprobacion", 1000)
    now = _now()
    until = now + timedelta(days=row.requested_days)
    await set_acceptance(org_id, row.vuln_id, "accept", f"Excepcion {row.id[:8]} aprobada por {actor} hasta {until.date().isoformat()}", actor)
    row.status, row.decided_by, row.decided_at, row.decision_note, row.expires_at = "approved", actor[:255], now, note, until
    await db.flush()
    self_approved = actor.strip().lower() == row.requested_by.strip().lower()
    await _log(db, org_id, "approved", actor, row, expires_at=until.isoformat(), approver_role=role, self_approved=self_approved,
               note_sha256=core.sha256_hex(note))
    return row


async def reject(db: AsyncSession, org_id: str | None, actor: str, role: str, row: RiskException, note: str) -> RiskException:
    if row.status != "pending":
        raise ExceptionError("Solo se decide una excepcion pendiente", 409)
    if row.vuln_severity == "critical" and role != "admin":
        raise ExceptionError("Una vulnerabilidad critica solo la puede decidir un administrador", 403)
    note = _clean_text(note, 10, "El motivo del rechazo", 1000)
    row.status, row.decided_by, row.decided_at, row.decision_note = "rejected", actor[:255], _now(), note
    row.ended_at, row.end_reason = row.decided_at, "Rechazada"
    await db.flush()
    await _log(db, org_id, "rejected", actor, row, note_sha256=core.sha256_hex(note))
    return row


async def withdraw(db: AsyncSession, org_id: str | None, actor: str, row: RiskException) -> RiskException:
    if row.status != "pending":
        raise ExceptionError("Solo se retira una excepcion pendiente", 409)
    if actor.strip().lower() != row.requested_by.strip().lower():
        raise ExceptionError("Solo quien la pidio puede retirarla", 403)
    row.status, row.ended_at, row.end_reason = "withdrawn", _now(), "Retirada por quien la pidio"
    await db.flush()
    await _log(db, org_id, "withdrawn", actor, row)
    return row


async def revoke(db: AsyncSession, org_id: str | None, actor: str, row: RiskException, note: str) -> RiskException:
    if row.status != "approved":
        raise ExceptionError("Solo se revoca una excepcion vigente", 409)
    note = _clean_text(note, 10, "El motivo de la revocacion", 1000)
    try:
        await set_acceptance(org_id, row.vuln_id, "reopen", f"Excepcion {row.id[:8]} revocada por {actor}", actor)
    except ExceptionError as exc:
        if exc.status != 409:  # 409: ya no estaba como riesgo aceptado, la excepcion igual se da por terminada
            raise
    row.status, row.ended_at, row.end_reason = "revoked", _now(), f"Revocada por {actor}: {note}"[:300]
    await db.flush()
    await _log(db, org_id, "revoked", actor, row, note_sha256=core.sha256_hex(note))
    return row


async def expire_due(db: AsyncSession, org_id: str | None = None, now: datetime | None = None) -> int:
    """Vence las excepciones aprobadas cuya fecha paso y reabre la vulnerabilidad. Devuelve cuantas vencio."""
    now = now or _now()
    q = select(RiskException).where(RiskException.status == "approved", RiskException.expires_at <= now)
    if org_id is not None:
        q = q.where(RiskException.organization_id == org_id)
    rows = (await db.execute(q)).scalars().all()
    done = 0
    for row in rows:
        reason = "Vencio la fecha de la excepcion"
        try:
            await set_acceptance(row.organization_id, row.vuln_id, "reopen", f"Excepcion {row.id[:8]} vencida: la vulnerabilidad vuelve a estar abierta", "sistema")
        except ExceptionError as exc:
            if exc.status == 409:
                reason = "Vencio, pero la vulnerabilidad ya no estaba como riesgo aceptado"
            elif exc.status == 404:
                reason = "Vencio; la vulnerabilidad ya no existe"
            else:
                logger.warning("no se pudo reabrir la vulnerabilidad de una excepcion vencida", extra={"exception_id": row.id})
                continue  # se reintenta en la proxima vuelta; la excepcion sigue "vigente" hasta lograrlo
        row.status, row.ended_at, row.end_reason = "expired", now, reason
        await db.flush()
        await _log(db, row.organization_id, "expired", "sistema", row, reason=reason)
        done += 1
    return done


async def loop(session_factory) -> None:
    while True:
        try:
            async with session_factory() as db:
                n = await expire_due(db)
                await db.commit()
                if n:
                    logger.info("excepciones de riesgo vencidas", extra={"count": n})
        except Exception:
            logger.exception("fallo el ciclo de vencimiento de excepciones de riesgo")
        await asyncio.sleep(CHECK_EVERY_SECONDS)


# ----------------------------- vistas y exportes -----------------------------

def view(row: RiskException, now: datetime | None = None, full: bool = True) -> dict:
    now = now or _now()
    until = _aware(row.expires_at)
    days_left = None
    if row.status == "approved" and until:
        days_left = max(0, (until - now).days)
    out = {
        "id": row.id, "vuln_id": row.vuln_id, "vuln_title": row.vuln_title, "severity": row.vuln_severity, "cve_id": row.cve_id,
        "status": row.status, "status_label": STATUS_LABEL.get(row.status, row.status), "requested_by": row.requested_by,
        "requested_at": _iso(row.requested_at), "requested_days": row.requested_days, "decided_by": row.decided_by,
        "decided_at": _iso(row.decided_at), "expires_at": _iso(row.expires_at), "days_left": days_left,
        "expiring_soon": days_left is not None and days_left <= EXPIRING_SOON_DAYS, "ended_at": _iso(row.ended_at),
        "end_reason": row.end_reason, "max_days": max_days_for(row.vuln_severity),
    }
    if full:
        out.update(justification=row.justification, compensating_controls=row.compensating_controls, decision_note=row.decision_note)
    return out


async def list_rows(db: AsyncSession, org_id: str | None, status: str | None = None, vuln_id: str | None = None) -> list[RiskException]:
    q = select(RiskException).where(RiskException.organization_id == org_id)
    if status:
        q = q.where(RiskException.status == status)
    if vuln_id:
        q = q.where(RiskException.vuln_id == vuln_id)
    rows = (await db.execute(q)).scalars().all()
    order = {"pending": 0, "approved": 1}
    return sorted(rows, key=lambda r: (order.get(r.status, 2), -(_aware(r.requested_at).timestamp())))


def summarize(rows: list[RiskException], now: datetime | None = None) -> dict:
    now = now or _now()
    views = [view(r, now, full=False) for r in rows]
    recent = now - timedelta(days=30)
    return {
        "pending": sum(1 for v in views if v["status"] == "pending"),
        "active": sum(1 for v in views if v["status"] == "approved"),
        "active_critical_or_high": sum(1 for v in views if v["status"] == "approved" and v["severity"] in ("critical", "high")),
        "expiring_soon": sum(1 for v in views if v["expiring_soon"]),
        "expired_last_30_days": sum(1 for r in rows if r.status == "expired" and r.ended_at and _aware(r.ended_at) >= recent),
        "rejected_last_30_days": sum(1 for r in rows if r.status == "rejected" and r.ended_at and _aware(r.ended_at) >= recent),
        "total": len(rows), "self_approval_allowed": allow_self_approval(),
    }


def register_csv(rows: list[RiskException]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Vulnerabilidad", "CVE", "Severidad", "Estado", "Pidio", "Fecha de pedido", "Aprobo o rechazo", "Fecha de decision",
                "Vence", "Dias pedidos", "Motivo del cierre"])
    for r in rows:
        w.writerow([_safe(r.vuln_title), r.cve_id, r.vuln_severity, STATUS_LABEL.get(r.status, r.status), r.requested_by,
                    (_iso(r.requested_at) or "")[:10], r.decided_by, (_iso(r.decided_at) or "")[:10],
                    (_iso(r.expires_at) or "")[:10], r.requested_days, _safe(r.end_reason)])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def _safe(value: str) -> str:
    value = value or ""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


async def make_attestation(db: AsyncSession, org_id: str | None, row: RiskException) -> dict:
    _total, entries = await custody.list_entries(db, org_id, limit=200, subject_id=row.id)
    history = [custody.entry_to_dict(e) for e in entries if e.event_type.startswith("risk_exception.")]
    chain = await custody.verify(db, org_id)
    body = {
        "exception": view(row), "history": [{k: e[k] for k in ("seq", "ts", "event_type", "actor")} | {"status": e["payload"].get("status", "")}
                                            for e in reversed(history)],
        "custody_entries": [{k: e[k] for k in ("seq", "ts", "prev_hash", "entry_hash", "signature")} for e in reversed(history)],
        "chain_ok_at_signing": bool(chain["ok"]), "chain_entries": chain["entries"], "chain_head": chain["head_hash"],
        "meaning": ("Prueba que el sistema registro, en las fechas indicadas, quien pidio aceptar el riesgo de esta vulnerabilidad, con que "
                    "justificacion y controles compensatorios, quien lo decidio y hasta cuando valia. No prueba que los controles "
                    "compensatorios estuvieran realmente implementados."),
    }
    return core.make_attestation("risk_exception", org_id, body)
