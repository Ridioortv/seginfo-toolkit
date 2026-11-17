"""Logica del riesgo de proveedores: altas, cuestionarios por link, evidencia, puntaje, resumen y atestado firmado."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from app import custody_service as custody
from app import vendor_catalog as cat
from app.vendor_models import Vendor, VendorAssessment, VendorEvidence

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class VendorError(Exception):
    """Dato invalido o accion no permitida; el mensaje es apto para mostrarle al usuario."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return cat._aware(dt)


def _iso(dt: datetime | None) -> str | None:
    dt = _aware(dt)
    return dt.isoformat() if dt else None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ----------------------------- validacion -----------------------------

def clean_domain(value: str) -> str:
    v = (value or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not v:
        return ""
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        raise VendorError("El dominio no es valido")
    if not _DOMAIN.match(v):
        raise VendorError("El dominio no es valido (ejemplo: proveedor.com)")
    return v


def clean_email(value: str, required: bool = False) -> str:
    v = (value or "").strip().lower()
    if not v:
        if required:
            raise VendorError("Escribi un email")
        return ""
    if not _EMAIL.match(v):
        raise VendorError("El email no es valido")
    return v


def clean_fields(data: dict) -> dict:
    """Normaliza y valida los campos editables de un proveedor (solo los presentes)."""
    out: dict = {}
    if "name" in data:
        name = (data["name"] or "").strip()
        if not name:
            raise VendorError("El nombre del proveedor no puede estar vacio")
        out["name"] = name[:255]
    if "domain" in data:
        out["domain"] = clean_domain(data["domain"] or "")
    if "criticality" in data:
        if data["criticality"] not in cat.CRITICALITY:
            raise VendorError("La criticidad debe ser critical, high, medium o low")
        out["criticality"] = data["criticality"]
    if "data_types" in data:
        types = list(dict.fromkeys(data["data_types"] or []))
        if any(t not in cat.DATA_TYPES for t in types):
            raise VendorError("Hay tipos de datos desconocidos")
        out["data_types"] = types
    for key, limit in (("service_description", 2000), ("owner", 255), ("notes", 2000)):
        if key in data:
            out[key] = (data[key] or "").strip()[:limit]
    if "contact_email" in data:
        out["contact_email"] = clean_email(data["contact_email"] or "")
    if "status" in data:
        if data["status"] not in ("active", "offboarded"):
            raise VendorError("El estado debe ser active u offboarded")
        out["status"] = data["status"]
    if "contract_end" in data:
        out["contract_end"] = data["contract_end"]
    return out


# ----------------------------- altas y cambios -----------------------------

async def get_vendor(db: AsyncSession, org_id: str | None, vendor_id: str) -> Vendor | None:
    return (await db.execute(select(Vendor).where(Vendor.id == vendor_id, Vendor.organization_id == org_id))).scalars().first()


async def create_vendor(db: AsyncSession, org_id: str | None, actor: str, data: dict) -> Vendor:
    fields = clean_fields(data)
    if "name" not in fields:
        raise VendorError("El nombre del proveedor es obligatorio")
    dup = (await db.execute(select(Vendor).where(Vendor.organization_id == org_id, Vendor.status == "active"))).scalars().all()
    if any(v.name.strip().lower() == fields["name"].lower() for v in dup):
        raise VendorError("Ya existe un proveedor activo con ese nombre", 409)
    vendor = Vendor(organization_id=org_id, created_by=actor[:255], **fields)
    db.add(vendor)
    await db.flush()
    await custody.append(
        db, org_id, "vendor.created", actor=actor, source="case-service", subject_type="vendor", subject_id=vendor.id,
        payload={"name": vendor.name, "criticality": vendor.criticality, "data_types": vendor.data_types})
    return vendor


async def update_vendor(db: AsyncSession, org_id: str | None, actor: str, vendor: Vendor, data: dict) -> Vendor:
    fields = clean_fields(data)
    changes = {k: v for k, v in fields.items() if getattr(vendor, k) != v}
    for k, v in changes.items():
        setattr(vendor, k, v)
    if changes:
        await db.flush()
        await custody.append(
            db, org_id, "vendor.updated", actor=actor, source="case-service", subject_type="vendor", subject_id=vendor.id,
            payload={"name": vendor.name, "changed": sorted(changes),
                     **{k: changes[k] for k in ("criticality", "status") if k in changes}})
    return vendor


# ----------------------------- cuestionarios -----------------------------

async def create_assessment(db: AsyncSession, org_id: str | None, actor: str, vendor: Vendor,
                            days: int = cat.DEFAULT_LINK_DAYS) -> tuple[VendorAssessment, str]:
    if vendor.status != "active":
        raise VendorError("El proveedor esta dado de baja", 409)
    days = max(1, min(int(days or cat.DEFAULT_LINK_DAYS), 90))
    token = secrets.token_urlsafe(32)
    row = VendorAssessment(
        organization_id=org_id, vendor_id=vendor.id, token_hash=hash_token(token), template_version=cat.TEMPLATE_VERSION,
        created_by=actor[:255], expires_at=_now() + timedelta(days=days))
    db.add(row)
    await db.flush()
    await custody.append(
        db, org_id, "vendor.assessment_sent", actor=actor, source="case-service", subject_type="vendor", subject_id=vendor.id,
        payload={"vendor": vendor.name, "assessment_id": row.id, "expires_at": row.expires_at.isoformat(),
                 "template": cat.TEMPLATE_VERSION})
    return row, token


async def get_assessment(db: AsyncSession, org_id: str | None, vendor_id: str, assessment_id: str) -> VendorAssessment | None:
    return (await db.execute(select(VendorAssessment).where(
        VendorAssessment.id == assessment_id, VendorAssessment.vendor_id == vendor_id,
        VendorAssessment.organization_id == org_id))).scalars().first()


async def cancel_assessment(db: AsyncSession, org_id: str | None, actor: str, vendor: Vendor, row: VendorAssessment) -> None:
    if row.status != "sent":
        raise VendorError("Solo se puede cancelar un cuestionario pendiente", 409)
    row.status = "cancelled"
    await db.flush()
    await custody.append(
        db, org_id, "vendor.assessment_cancelled", actor=actor, source="case-service", subject_type="vendor",
        subject_id=vendor.id, payload={"vendor": vendor.name, "assessment_id": row.id})


def assessment_state(row: VendorAssessment, now: datetime | None = None) -> str:
    now = now or _now()
    if row.status == "sent" and _aware(row.expires_at) <= now:
        return "expired"
    return row.status


async def find_by_token(db: AsyncSession, token: str) -> VendorAssessment | None:
    if not token or len(token) > 100:
        return None
    return (await db.execute(select(VendorAssessment).where(VendorAssessment.token_hash == hash_token(token)))).scalars().first()


async def submit_assessment(db: AsyncSession, row: VendorAssessment, respondent_name: str, respondent_email: str,
                            raw_answers: object) -> VendorAssessment:
    state = assessment_state(row)
    if state == "completed":
        raise VendorError("Este cuestionario ya fue respondido", 409)
    if state in ("expired", "cancelled"):
        raise VendorError("Este link ya no esta vigente. Pedi uno nuevo a quien te lo envio.", 410)
    name = (respondent_name or "").strip()
    if len(name) < 2:
        raise VendorError("Escribi tu nombre")
    email = clean_email(respondent_email, required=True)
    try:
        answers = cat.validate_answers(raw_answers)
    except cat.AnswerError as exc:
        raise VendorError(str(exc))
    detail = cat.control_score(answers)
    vendor = (await db.execute(select(Vendor).where(Vendor.id == row.vendor_id))).scalars().first()
    row.status, row.completed_at = "completed", _now()
    row.respondent_name, row.respondent_email = name[:255], email
    row.answers = core.canonical(answers)
    row.answers_sha256 = core.sha256_hex(row.answers)
    row.score_base, row.score_detail = detail["base"], core.canonical(detail)
    await db.flush()
    await custody.append(
        db, row.organization_id, "vendor.assessment_completed", actor=f"proveedor:{email}", source="case-service",
        subject_type="vendor", subject_id=row.vendor_id,
        payload={"vendor": vendor.name if vendor else "", "assessment_id": row.id, "score_base": detail["base"],
                 "knockouts": detail["knockouts"], "answers_sha256": row.answers_sha256, "respondent": name[:100]})
    return row


# ----------------------------- evidencia -----------------------------

async def add_evidence(db: AsyncSession, org_id: str | None, actor: str, vendor: Vendor, data: dict) -> VendorEvidence:
    kind = data.get("kind")
    if kind not in cat.EVIDENCE_KINDS:
        raise VendorError("Tipo de evidencia desconocido")
    title = (data.get("title") or "").strip()
    if len(title) < 3:
        raise VendorError("Escribi un titulo de al menos 3 caracteres")
    sha = (data.get("document_sha256") or "").strip().lower()
    if sha and not _SHA256.match(sha):
        raise VendorError("La huella SHA-256 debe tener 64 caracteres hexadecimales")
    url = (data.get("reference_url") or "").strip()
    if url and not re.match(r"^https?://[^\s]{3,480}$", url):
        raise VendorError("El link de referencia debe empezar con http:// o https://")
    issued, until = data.get("issued_at"), data.get("valid_until")
    if issued and until and _aware(until) <= _aware(issued):
        raise VendorError("El vencimiento tiene que ser posterior a la fecha de emision")
    row = VendorEvidence(
        organization_id=org_id, vendor_id=vendor.id, kind=kind, title=title[:255], issued_at=issued, valid_until=until,
        reference_url=url, document_sha256=sha, note=(data.get("note") or "").strip()[:1000], added_by=actor[:255])
    db.add(row)
    await db.flush()
    await custody.append(
        db, org_id, "vendor.evidence_added", actor=actor, source="case-service", subject_type="vendor", subject_id=vendor.id,
        payload={"vendor": vendor.name, "evidence_id": row.id, "kind": kind, "title": row.title,
                 "valid_until": _iso(until), "document_sha256": sha})
    return row


async def remove_evidence(db: AsyncSession, org_id: str | None, actor: str, vendor: Vendor, evidence_id: str) -> bool:
    row = (await db.execute(select(VendorEvidence).where(
        VendorEvidence.id == evidence_id, VendorEvidence.vendor_id == vendor.id,
        VendorEvidence.organization_id == org_id))).scalars().first()
    if row is None:
        return False
    await db.delete(row)
    await custody.append(
        db, org_id, "vendor.evidence_removed", actor=actor, source="case-service", subject_type="vendor", subject_id=vendor.id,
        payload={"vendor": vendor.name, "evidence_id": evidence_id, "kind": row.kind, "title": row.title})
    return True


# ----------------------------- vistas -----------------------------

def evidence_view(e: VendorEvidence, now: datetime) -> dict:
    return {"id": e.id, "kind": e.kind, "kind_label": cat.EVIDENCE_LABEL.get(e.kind, e.kind), "title": e.title,
            "issued_at": _iso(e.issued_at), "valid_until": _iso(e.valid_until), "status": cat.evidence_status(e.valid_until, now),
            "reference_url": e.reference_url, "document_sha256": e.document_sha256, "note": e.note,
            "added_by": e.added_by, "added_at": _iso(e.added_at)}


def assessment_view(a: VendorAssessment, now: datetime, with_answers: bool = False) -> dict:
    out = {"id": a.id, "status": assessment_state(a, now), "created_by": a.created_by, "created_at": _iso(a.created_at),
           "expires_at": _iso(a.expires_at), "completed_at": _iso(a.completed_at), "respondent_name": a.respondent_name,
           "respondent_email": a.respondent_email, "score_base": a.score_base,
           "score_detail": json.loads(a.score_detail or "{}"), "template_version": a.template_version}
    if with_answers:
        answers = json.loads(a.answers or "{}")
        out["answers"] = [{"id": q["id"], "domain": q["domain"], "text": q["text"], "knockout": q["knockout"],
                           **answers.get(q["id"], {"answer": "", "comment": ""})} for q in cat.QUESTIONS]
    return out


def _latest_completed(assessments: list[VendorAssessment]) -> VendorAssessment | None:
    done = [a for a in assessments if a.status == "completed" and a.completed_at]
    return max(done, key=lambda a: _aware(a.completed_at)) if done else None


def vendor_view(v: Vendor, assessments: list[VendorAssessment], evidence: list[VendorEvidence], now: datetime,
                detail: bool = False) -> dict:
    ev = [evidence_view(e, now) for e in evidence]
    last = _latest_completed(assessments)
    risk = cat.assess(v.criticality, {"score_detail": json.loads(last.score_detail or "{}"), "completed_at": last.completed_at}
                      if last else None, ev, now)
    pending = [a for a in assessments if assessment_state(a, now) == "sent"]
    contract_end = _aware(v.contract_end)
    out = {
        "id": v.id, "name": v.name, "domain": v.domain, "criticality": v.criticality,
        "criticality_label": cat.CRITICALITY_LABEL.get(v.criticality, v.criticality), "service_description": v.service_description,
        "data_types": v.data_types or [], "owner": v.owner, "contact_email": v.contact_email, "status": v.status,
        "contract_end": _iso(v.contract_end), "notes": v.notes, "created_at": _iso(v.created_at), "created_by": v.created_by,
        "risk": {**risk, "level_label": cat.LEVEL_LABEL[risk["level"]]},
        "last_assessment_at": _iso(last.completed_at) if last else None,
        "pending_assessment": bool(pending),
        "evidence_counts": {s: sum(1 for e in ev if e["status"] == s) for s in ("vigente", "por_vencer", "vencida")},
        "contract_expiring": bool(contract_end and v.status == "active" and contract_end <= now + timedelta(days=60)),
    }
    if detail:
        out["evidence"] = ev
        out["assessments"] = [assessment_view(a, now) for a in sorted(assessments, key=lambda a: _aware(a.created_at), reverse=True)]
    return out


async def _load(db: AsyncSession, org_id: str | None, vendor_ids: list[str] | None = None):
    qa = select(VendorAssessment).where(VendorAssessment.organization_id == org_id)
    qe = select(VendorEvidence).where(VendorEvidence.organization_id == org_id)
    if vendor_ids is not None:
        qa, qe = qa.where(VendorAssessment.vendor_id.in_(vendor_ids)), qe.where(VendorEvidence.vendor_id.in_(vendor_ids))
    a_by: dict[str, list] = {}
    e_by: dict[str, list] = {}
    for a in (await db.execute(qa)).scalars().all():
        a_by.setdefault(a.vendor_id, []).append(a)
    for e in (await db.execute(qe)).scalars().all():
        e_by.setdefault(e.vendor_id, []).append(e)
    return a_by, e_by


async def list_views(db: AsyncSession, org_id: str | None, include_offboarded: bool = False) -> list[dict]:
    q = select(Vendor).where(Vendor.organization_id == org_id)
    if not include_offboarded:
        q = q.where(Vendor.status == "active")
    vendors = (await db.execute(q.order_by(Vendor.name))).scalars().all()
    a_by, e_by = await _load(db, org_id)
    now = _now()
    rank = {"critical": 0, "high": 1, "stale": 2, "unassessed": 3, "medium": 4, "low": 5}
    views = [vendor_view(v, a_by.get(v.id, []), e_by.get(v.id, []), now) for v in vendors]
    views.sort(key=lambda x: (x["status"] != "active", rank.get(x["risk"]["level"], 9),
                              cat.CRITICALITY.index(x["criticality"]), x["name"].lower()))
    return views


async def detail_view(db: AsyncSession, org_id: str | None, vendor: Vendor) -> dict:
    a_by, e_by = await _load(db, org_id, [vendor.id])
    return vendor_view(vendor, a_by.get(vendor.id, []), e_by.get(vendor.id, []), _now(), detail=True)


def summarize(views: list[dict]) -> dict:
    active = [v for v in views if v["status"] == "active"]
    by_level = {lvl: sum(1 for v in active if v["risk"]["level"] == lvl) for lvl in cat.LEVELS}
    needs_attention = [v for v in active if v["criticality"] in ("critical", "high")
                       and v["risk"]["level"] in ("unassessed", "stale") and not v["pending_assessment"]]
    return {
        "total": len(active), "by_level": by_level,
        "critical_vendors": sum(1 for v in active if v["criticality"] == "critical"),
        "high_or_critical_risk": by_level["critical"] + by_level["high"],
        "without_assessment_critical_or_high": len(needs_attention),
        "pending_questionnaires": sum(1 for v in active if v["pending_assessment"]),
        "expired_evidence": sum(v["evidence_counts"]["vencida"] for v in active),
        "expiring_evidence": sum(v["evidence_counts"]["por_vencer"] for v in active),
        "contracts_expiring": sum(1 for v in active if v["contract_expiring"]),
    }


# ----------------------------- exportes -----------------------------

def report_csv(views: list[dict]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Proveedor", "Dominio", "Criticidad", "Datos que maneja", "Nivel de riesgo", "Indice", "Puntaje efectivo",
                "Ultima evaluacion", "Evidencia vigente", "Evidencia por vencer", "Evidencia vencida", "Fin de contrato", "Responsable"])
    for v in views:
        r = v["risk"]
        w.writerow([_safe(v["name"]), v["domain"], v["criticality_label"], ", ".join(v["data_types"]), r["level_label"],
                    "" if r["index"] is None else r["index"], "" if r["effective_score"] is None else r["effective_score"],
                    (v["last_assessment_at"] or "")[:10], v["evidence_counts"]["vigente"], v["evidence_counts"]["por_vencer"],
                    v["evidence_counts"]["vencida"], (v["contract_end"] or "")[:10], _safe(v["owner"])])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def _safe(value: str) -> str:
    """Evita que Excel interprete una celda como formula (inyeccion de CSV)."""
    value = value or ""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


LIMITS = [
    "El puntaje sale de un cuestionario que responde el propio proveedor; TERO no verifica cada respuesta.",
    "La evidencia cargada es una ficha con su vencimiento: TERO no valida el contenido de los documentos.",
    "El nivel de riesgo es una ayuda para priorizar el seguimiento; no certifica ni descalifica a un proveedor.",
]


async def make_attestation(db: AsyncSession, org_id: str | None, actor: str) -> dict:
    views = await list_views(db, org_id)
    now = _now()
    body = {
        "generated_for": "Riesgo de proveedores (terceros)", "evaluated_at": now.isoformat(), "method": {
            "template": cat.TEMPLATE_VERSION, "questions": len(cat.QUESTIONS), "assessment_valid_days": cat.ASSESSMENT_VALID_DAYS,
            "risk_formula": "indice = peso_criticidad x (100 - puntaje_efectivo); >=50 critico, >=30 alto, >=15 medio, <15 bajo; un 'no' en un control basico nunca deja el riesgo en bajo",
        },
        "summary": summarize(views),
        "vendors": [{
            "name": v["name"], "domain": v["domain"], "criticality": v["criticality"], "data_types": v["data_types"],
            "risk_level": v["risk"]["level"], "risk_index": v["risk"]["index"], "effective_score": v["risk"]["effective_score"],
            "last_assessment_at": v["last_assessment_at"], "evidence": v["evidence_counts"], "contract_end": v["contract_end"],
        } for v in views],
        "limits": LIMITS,
    }
    doc = core.make_attestation("vendor", org_id, body)
    await custody.append(
        db, org_id, "vendor.attestation", actor=actor, source="case-service", subject_type="vendor", subject_id="organization",
        payload={"vendors": len(views), "body_sha256": core.sha256_hex(core.canonical(doc["body"])), "signature": doc["signature"][:32]})
    return doc
