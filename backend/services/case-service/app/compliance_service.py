"""Cumplimiento con evidencia viva: evalua el catalogo contra datos reales, junta las declaraciones manuales,
completa el cuestionario de seguro, guarda fotos para ver la evolucion y firma un atestado.

Idea central: lo VERIFICADO por TERO y lo DECLARADO por una persona nunca se mezclan en el mismo numero sin
decirlo. Cada control dice de donde sale su estado (`basis`: verificado | declarado | ninguno)."""
from __future__ import annotations

import asyncio
import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from backend.shared.logging import configure_logging
from app import compliance_catalog as cat
from app import compliance_evidence as evidence
from app import custody_service as custody
from app.compliance_models import ComplianceDeclaration, ComplianceSnapshot

logger = configure_logging("compliance")
SNAPSHOT_EVERY_HOURS = float(os.getenv("COMPLIANCE_SNAPSHOT_HOURS", "24"))
DEFAULT_VALID_MONTHS = 12
YES, PARTIAL, NO, UNKNOWN = "yes", "partial", "no", "unknown"
POINTS = {"cumple": 1.0, "declarado_si": 1.0, "parcial": 0.5, "declarado_parcial": 0.5}
_TO_ANSWER = {"cumple": YES, "declarado_si": YES, "parcial": PARTIAL, "declarado_parcial": PARTIAL,
              "no_cumple": NO, "declarado_no": NO}
STATUSES = ("cumple", "parcial", "no_cumple", "declarado_si", "declarado_parcial", "declarado_no", "pendiente",
            "vencido", "sin_datos")


class ComplianceError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def render(summary: dict) -> str:
    """Texto final (en espanol) de un resumen {text, args} -- para el CSV y el atestado."""
    try:
        return summary["text"].format(*summary.get("args", []))
    except (IndexError, KeyError, ValueError):
        return summary.get("text", "")


# ----------------------------- declaraciones -----------------------------

async def declarations(db: AsyncSession, org_id: str | None) -> dict[str, ComplianceDeclaration]:
    rows = (await db.execute(select(ComplianceDeclaration).where(ComplianceDeclaration.organization_id == org_id))).scalars().all()
    return {r.control_id: r for r in rows}


def _decl_status(decl: ComplianceDeclaration, now: datetime) -> str:
    until = _aware(decl.valid_until)
    if until is not None and until < now:
        return "vencido"
    return {"yes": "declarado_si", "partial": "declarado_parcial", "no": "declarado_no"}[decl.answer]


def _decl_view(decl: ComplianceDeclaration | None, now: datetime) -> dict | None:
    if decl is None:
        return None
    return {"answer": decl.answer, "note": decl.note, "declared_by": decl.declared_by,
            "declared_at": _aware(decl.declared_at).isoformat() if decl.declared_at else "",
            "valid_until": _aware(decl.valid_until).isoformat() if decl.valid_until else None,
            "expired": _decl_status(decl, now) == "vencido"}


async def declare(db: AsyncSession, org_id: str | None, actor: str, control_id: str, answer: str, note: str,
                  valid_months: int = DEFAULT_VALID_MONTHS) -> ComplianceDeclaration:
    if control_id not in cat.CONTROL_BY_ID:
        raise ComplianceError("Control desconocido")
    if answer not in ("yes", "partial", "no"):
        raise ComplianceError("La respuesta debe ser yes, partial o no")
    note = (note or "").strip()
    if len(note) < 10:
        raise ComplianceError("Escribi una nota de al menos 10 caracteres: que existe, donde esta y quien lo sabe")
    months = max(1, min(int(valid_months or DEFAULT_VALID_MONTHS), 24))
    now = _now()
    until = now + timedelta(days=30 * months)
    existing = (await db.execute(select(ComplianceDeclaration).where(
        ComplianceDeclaration.organization_id == org_id, ComplianceDeclaration.control_id == control_id))).scalars().first()
    row = existing or ComplianceDeclaration(organization_id=org_id, control_id=control_id)
    row.answer, row.note, row.declared_by, row.declared_at, row.valid_until = answer, note[:2000], actor[:255], now, until
    db.add(row)
    await custody.append(
        db, org_id, "compliance.declaration", actor=actor, source="case-service", subject_type="compliance",
        subject_id=control_id, payload={"control_id": control_id, "answer": answer,
                                        "note_sha256": core.sha256_hex(note), "valid_until": until.isoformat()})
    await db.flush()
    return row


async def remove_declaration(db: AsyncSession, org_id: str | None, actor: str, control_id: str) -> bool:
    res = await db.execute(delete(ComplianceDeclaration).where(
        ComplianceDeclaration.organization_id == org_id, ComplianceDeclaration.control_id == control_id))
    if not res.rowcount:
        return False
    await custody.append(db, org_id, "compliance.declaration_removed", actor=actor, source="case-service",
                         subject_type="compliance", subject_id=control_id, payload={"control_id": control_id})
    return True


# ----------------------------- evaluacion -----------------------------

def _item(control: dict, status: str, basis: str, summary: dict, ev_list: list[dict], decl: dict | None) -> dict:
    return {"id": control["id"], "area": control["area"], "area_label": cat.AREAS[control["area"]],
            "title": control["title"], "why": control["why"], "refs": control["refs"], "mode": control["mode"],
            "status": status, "basis": basis, "summary": summary, "evidence": ev_list, "declaration": decl}


def evaluate_controls(facts: dict, decls: dict[str, ComplianceDeclaration], now: datetime | None = None) -> list[dict]:
    now = now or _now()
    out = []
    for c in cat.CONTROLS:
        decl = decls.get(c["id"])
        view = _decl_view(decl, now)
        if c["mode"] == "auto":
            r = evidence.run_check(c["check"], facts)
            if r["status"] == "sin_datos" and decl is not None and _decl_status(decl, now) != "vencido":
                out.append(_item(c, _decl_status(decl, now), "declarado",
                                 evidence.m("TERO no pudo comprobarlo solo; una persona lo declaro: {0}", decl.note[:200]),
                                 r["evidence"], view))
            else:
                out.append(_item(c, r["status"], "verificado" if r["status"] != "sin_datos" else "ninguno",
                                 r["summary"], r["evidence"], view))
            continue
        if decl is None:
            out.append(_item(c, "pendiente", "ninguno", evidence.m("Nadie lo declaro todavia. TERO no puede comprobarlo solo."), [], None))
        else:
            st = _decl_status(decl, now)
            summary = (evidence.m("La declaracion vencio: hay que renovarla.") if st == "vencido"
                       else evidence.m("Declarado por {0}: {1}", decl.declared_by, decl.note[:200]))
            out.append(_item(c, st, "declarado", summary, [], view))
    return out


def scores(items: list[dict]) -> dict:
    verified = [i for i in items if i["basis"] == "verificado"]
    pts_v = sum(POINTS.get(i["status"], 0.0) for i in verified)
    pts_t = sum(POINTS.get(i["status"], 0.0) for i in items)
    counts = {s: 0 for s in STATUSES}
    for i in items:
        counts[i["status"]] += 1
    by_area: dict[str, dict] = {}
    for i in items:
        b = by_area.setdefault(i["area"], {"label": i["area_label"], "total": 0, "points": 0.0})
        b["total"] += 1
        b["points"] += POINTS.get(i["status"], 0.0)
    return {
        "score_verified": round(100 * pts_v / len(verified), 1) if verified else None,
        "verified_controls": len(verified),
        "automatic_controls": sum(1 for i in items if i["mode"] == "auto"),
        "score_total": round(100 * pts_t / len(items), 1) if items else None,
        "total_controls": len(items), "counts": counts,
        "by_area": {k: {"label": v["label"], "total": v["total"], "score": round(100 * v["points"] / v["total"], 1)}
                    for k, v in by_area.items()},
    }


def questionnaire(items: list[dict]) -> list[dict]:
    by_id = {i["id"]: i for i in items}
    out = []
    for q in cat.INSURANCE_QUESTIONS:
        states = [_TO_ANSWER.get(by_id[cid]["status"], UNKNOWN) for cid in q["controls"]]
        if all(s == YES for s in states):
            answer = YES
        elif NO in states and YES not in states and PARTIAL not in states:
            answer = NO
        elif UNKNOWN in states and NO not in states:
            answer = "pending"
        else:
            answer = PARTIAL
        out.append({
            "id": q["id"], "text": q["text"], "answer": answer,
            "controls": [{"id": cid, "title": by_id[cid]["title"], "status": by_id[cid]["status"], "basis": by_id[cid]["basis"],
                          "summary": by_id[cid]["summary"]} for cid in q["controls"]],
        })
    return out


async def evaluate(db: AsyncSession, org_id: str | None, client=None) -> dict:
    now = _now()
    facts = await evidence.gather(db, org_id, client)
    decls = await declarations(db, org_id)
    items = evaluate_controls(facts, decls, now)
    return {"evaluated_at": now.isoformat(), "organization_id": org_id or "", "disclaimer": cat.DISCLAIMER,
            "summary": scores(items), "controls": items, "questionnaire": questionnaire(items)}


# ----------------------------- fotos y atestado -----------------------------

def _compact(ev: dict) -> dict:
    return {"id": ev["id"], "title": ev["title"], "status": ev["status"], "basis": ev["basis"], "refs": ev["refs"],
            "detail": render(ev["summary"]),
            "observations": [{"label": e["label"], "value": e["value"], "source": e["source"]} for e in ev["evidence"]],
            "declaration": ev["declaration"]}


def attestation_body(ev: dict) -> dict:
    return {
        "evaluated_at": ev["evaluated_at"], "disclaimer": ev["disclaimer"],
        "legal_references": {"ley": "Ley 25.326 (art. 9, 10, 12, 14 a 16, 21)",
                             "recomendaciones": "Resolucion AAIP 47/2018, Anexo I (medidas recomendadas)",
                             "tecnica": "CIS Controls v8"},
        "score_verified": ev["summary"]["score_verified"], "score_total": ev["summary"]["score_total"],
        "verified_controls": ev["summary"]["verified_controls"], "total_controls": ev["summary"]["total_controls"],
        "counts": ev["summary"]["counts"],
        "controls": [_compact(c) for c in ev["controls"]],
        "questionnaire": [{"id": q["id"], "question": q["text"], "answer": q["answer"],
                           "controls": [{"id": c["id"], "status": c["status"], "basis": c["basis"]} for c in q["controls"]]}
                          for q in ev["questionnaire"]],
        "limits": LIMITS,
    }


LIMITS = [
    "Lo verificado sale de los datos de TERO en el momento de la evaluacion; no prueba lo que paso antes ni despues.",
    "Lo declarado lo afirma una persona: TERO guarda quien, cuando y hasta cuando, pero no lo puede comprobar.",
    "El puntaje es una ayuda para ordenar el trabajo; no es una certificacion ni asegura el resultado de una auditoria o una renovacion de seguro.",
]


async def make_snapshot(db: AsyncSession, org_id: str | None, actor: str, ev: dict | None = None) -> ComplianceSnapshot:
    ev = ev or await evaluate(db, org_id)
    body = attestation_body(ev)
    sha = core.sha256_hex(core.canonical(body))
    s = ev["summary"]
    snap = ComplianceSnapshot(
        organization_id=org_id, actor=actor[:255], score_verified=s["score_verified"], score_total=s["score_total"],
        counts=json.dumps(s["counts"]), controls=json.dumps({c["id"]: c["status"] for c in ev["controls"]}),
        body_sha256=sha, total_controls=s["total_controls"])
    db.add(snap)
    await custody.append(
        db, org_id, "compliance.snapshot", actor=actor, source="case-service", subject_type="compliance",
        subject_id="organization", payload={"score_verified": s["score_verified"], "score_total": s["score_total"],
                                           "verified_controls": s["verified_controls"], "body_sha256": sha})
    await db.flush()
    return snap


async def history(db: AsyncSession, org_id: str | None, limit: int = 60) -> list[dict]:
    rows = (await db.execute(select(ComplianceSnapshot).where(ComplianceSnapshot.organization_id == org_id)
                             .order_by(ComplianceSnapshot.created_at.desc()).limit(limit))).scalars().all()
    return [{"id": r.id, "created_at": _aware(r.created_at).isoformat(), "actor": r.actor,
             "score_verified": r.score_verified, "score_total": r.score_total, "counts": json.loads(r.counts or "{}")}
            for r in reversed(rows)]


async def make_attestation(db: AsyncSession, org_id: str | None, actor: str) -> dict:
    ev = await evaluate(db, org_id)
    doc = core.make_attestation("compliance", org_id, attestation_body(ev))
    await custody.append(
        db, org_id, "compliance.attestation", actor=actor, source="case-service", subject_type="compliance",
        subject_id="organization", payload={"score_verified": ev["summary"]["score_verified"],
                                           "body_sha256": core.sha256_hex(core.canonical(doc["body"])),
                                           "signature": doc["signature"][:32]})
    return doc


_ANSWER_ES = {YES: "Si", NO: "No", PARTIAL: "Parcial", "pending": "Sin responder (falta evidencia o declaracion)"}


def questionnaire_csv(ev: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Id", "Pregunta", "Respuesta", "Controles", "Detalle de la evidencia"])
    for q in ev["questionnaire"]:
        detail = " | ".join(f"{c['id']} [{c['status']}/{c['basis']}]: {render(c['summary'])}" for c in q["controls"])
        row = [q["id"], q["text"], _ANSWER_ES[q["answer"]], ", ".join(c["id"] for c in q["controls"]), detail]
        w.writerow([custody._csv_safe(str(v)) for v in row])
    w.writerow([])
    w.writerow(["", "Generado por TERO el " + ev["evaluated_at"] + ". " + cat.DISCLAIMER])
    return ("﻿" + buf.getvalue()).encode("utf-8")


# ----------------------------- foto automatica -----------------------------

async def snapshot_loop(session_factory, org_ids_fn) -> None:
    """Una foto por organizacion cada SNAPSHOT_EVERY_HOURS (0 la apaga): asi se ve la evolucion sin que nadie
    se acuerde de apretar el boton."""
    if SNAPSHOT_EVERY_HOURS <= 0:
        return
    await asyncio.sleep(120)
    while True:
        try:
            for org in await org_ids_fn():
                async with session_factory() as db:
                    last = (await db.execute(select(ComplianceSnapshot.created_at).where(ComplianceSnapshot.organization_id == org)
                                             .order_by(ComplianceSnapshot.created_at.desc()).limit(1))).scalars().first()
                    if last is None or _now() - _aware(last) >= timedelta(hours=SNAPSHOT_EVERY_HOURS):
                        await make_snapshot(db, org, "system:case-service")
                        await db.commit()
        except Exception as exc:
            logger.warning("fallo la foto automatica de cumplimiento", extra={"error": str(exc)})
        await asyncio.sleep(3600)
