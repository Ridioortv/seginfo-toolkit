"""Tablero e informe ejecutivo para la direccion.

Reglas (para que un director pueda confiar en lo que lee):
  * Cada numero sale de datos reales de TERO (marcas de tiempo de cada vulnerabilidad, casos, excepciones, proveedores,
    cumplimiento, simulacros). No hay estimaciones: si una fuente no responde, esa parte dice "sin datos" y se lista en
    `sources`; nunca se completa con ceros.
  * Cada indicador se compara con el periodo anterior de la misma duracion.
  * El tiempo de correccion se muestra de dos maneras: DECLARADO (hasta que alguien marco "remediada") y REAL (hasta que
    TERO verifico el cierre con un nuevo escaneo). La diferencia es lo que la direccion necesita ver.
  * La exposicion por unidad de negocio pondera lo abierto: critica 10, alta 5, media 2, baja 0,5 (x1,5 si se explota
    activamente). Es una ayuda para priorizar, no una medida de perdida economica.
  * La lista "requiere atencion" sale de reglas fijas y explicables, no de un modelo.
  * El informe se firma (Ed25519) y se puede verificar offline con verificar_evidencia.py."""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from backend.shared.logging import configure_logging
from backend.shared.service_auth import service_auth_headers
from app import compliance_service
from app import custody_service as custody
from app import exception_service, vendor_service
from app.compliance_evidence import URLS, _get
from app.executive_models import ExecutiveSnapshot
from app.models import Case, CaseStatus

logger = configure_logging("executive")
UNASSIGNED = "(sin unidad asignada)"
SNAPSHOT_ENABLED = os.getenv("EXECUTIVE_SNAPSHOT_ENABLED", "true").lower() not in ("0", "false", "no")
KEEP_DAYS = 400
LIMITS = [
    "Los numeros salen de los datos de TERO en el momento indicado; no prueban lo que paso antes ni despues.",
    "La exposicion por unidad de negocio depende de que cada activo tenga su unidad asignada: lo que no la tiene figura aparte.",
    "El puntaje de exposicion es una ayuda para priorizar, no una medida de perdida economica.",
    "El tiempo real de correccion solo cuenta las vulnerabilidades cuyo cierre TERO pudo verificar con un nuevo escaneo.",
    "El informe no es una certificacion ni asegura el resultado de una auditoria.",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _ts(value) -> datetime | None:
    try:
        return _aware(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        return None


def m(text: str, *args) -> dict:
    return {"text": text, "args": [str(a) for a in args]}


def clamp_days(days: int | None) -> int:
    try:
        return max(7, min(int(days or 30), 365))
    except (TypeError, ValueError):
        return 30


def delta(current, previous) -> dict:
    """Valor actual, anterior y cambio. `change_pct` es None si no hay base de comparacion."""
    if current is None or previous is None:
        return {"current": current, "previous": previous, "change": None, "change_pct": None}
    change = round(current - previous, 2)
    pct = round(100.0 * change / previous, 1) if previous else None
    return {"current": current, "previous": previous, "change": change, "change_pct": pct}


# ----------------------------- casos (datos propios) -----------------------------

def cases_metrics(rows: list[tuple], now: datetime, days: int) -> dict:
    """rows: (status, created_at, resolved_at, sla_due_at)."""
    cur_start, prev_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    open_now = overdue = 0
    opened = {"cur": 0, "prev": 0}
    resolved = {"cur": 0, "prev": 0}
    hours = {"cur": [], "prev": []}
    sla_ok = sla_total = 0
    for status, created, resolved_at, sla_due in rows:
        status = getattr(status, "value", status)
        created, resolved_at, sla_due = _aware(created), _aware(resolved_at), _aware(sla_due)
        if status in ("open", "in_progress"):
            open_now += 1
            if sla_due is not None and sla_due < now:
                overdue += 1
        if created is not None:
            if cur_start <= created < now:
                opened["cur"] += 1
            elif prev_start <= created < cur_start:
                opened["prev"] += 1
        if resolved_at is not None:
            key = "cur" if cur_start <= resolved_at < now else "prev" if prev_start <= resolved_at < cur_start else None
            if key:
                resolved[key] += 1
                if created is not None:
                    hours[key].append(max(0.0, (resolved_at - created).total_seconds() / 3600))
                if key == "cur" and sla_due is not None:
                    sla_total += 1
                    sla_ok += 1 if resolved_at <= sla_due else 0

    def avg(v):
        return round(sum(v) / len(v), 1) if v else None

    return {"open": open_now, "overdue": overdue, "total": len(rows),
            "opened": delta(opened["cur"], opened["prev"]), "resolved": delta(resolved["cur"], resolved["prev"]),
            "mttr_hours": delta(avg(hours["cur"]), avg(hours["prev"])),
            "sla_met_pct": round(100.0 * sla_ok / sla_total, 1) if sla_total else None, "sla_measured": sla_total}


async def _cases(db: AsyncSession, org: str | None, now: datetime, days: int) -> dict:
    rows = (await db.execute(select(Case.status, Case.created_at, Case.resolved_at, Case.sla_due_at)
                             .where(Case.organization_id == org))).all()
    return cases_metrics([tuple(r) for r in rows], now, days)


# ----------------------------- exposicion por unidad de negocio -----------------------------

def exposure_by_unit(by_asset: list[dict], assets: list[dict]) -> dict:
    info = {a["id"]: a for a in assets if a.get("id")}
    units: dict[str, dict] = {}

    def unit(name: str) -> dict:
        return units.setdefault(name, {"unit": name, "assets": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                                       "kev": 0, "score": 0.0})

    for a in assets:
        unit((a.get("business_unit") or "").strip() or UNASSIGNED)["assets"] += 1
    top = []
    for row in by_asset:
        a = info.get(row["asset_id"])
        name = ((a or {}).get("business_unit") or "").strip() or UNASSIGNED
        u = unit(name)
        for k in ("critical", "high", "medium", "low", "kev"):
            u[k] += row.get(k, 0)
        u["score"] += row.get("score", 0.0)
        top.append({"asset_id": row["asset_id"], "hostname": (a or {}).get("hostname") or (a or {}).get("ip_address") or "",
                    "known": a is not None, "business_unit": name, "criticality": (a or {}).get("criticality", ""),
                    "critical": row.get("critical", 0), "high": row.get("high", 0), "medium": row.get("medium", 0),
                    "kev": row.get("kev", 0), "score": row.get("score", 0.0)})
    total = sum(u["score"] for u in units.values())
    out = []
    for u in units.values():
        u["score"] = round(u["score"], 1)
        u["share_pct"] = round(100.0 * u["score"] / total, 1) if total else 0.0
        out.append(u)
    out.sort(key=lambda u: (-u["score"], u["unit"] == UNASSIGNED, u["unit"].lower()))
    unassigned = next((u for u in out if u["unit"] == UNASSIGNED), None)
    return {"by_business_unit": out, "top_assets": top[:10], "total_score": round(total, 1),
            "unassigned_share_pct": unassigned["share_pct"] if unassigned and total else 0.0,
            "units_defined": sum(1 for u in out if u["unit"] != UNASSIGNED)}


# ----------------------------- armado -----------------------------

def _data(facts: dict, key: str):
    f = facts.get(key)
    return f["data"] if f and f.get("ok") else None


def attention_list(s: dict) -> list[dict]:
    """Reglas fijas: que mirar primero. level: critical | warning | info."""
    out: list[dict] = []

    def add(level: str, code: str, text: dict, link: str = ""):
        out.append({"level": level, "code": code, "message": text, "link": link})

    v, r = s.get("vulnerabilities"), s.get("remediation")
    if v:
        if v["kev"]:
            add("critical", "kev_open", m("{0} vulnerabilidades abiertas se estan explotando activamente en internet (lista KEV).", v["kev"]), "/vulnerabilities")
        if v["oldest_critical_high_days"] >= 90:
            add("critical", "oldest_90", m("Hay una vulnerabilidad critica o alta abierta hace {0} dias.", v["oldest_critical_high_days"]), "/vulnerabilities")
        elif v["oldest_critical_high_days"] >= 30:
            add("warning", "oldest_30", m("Hay una vulnerabilidad critica o alta abierta hace {0} dias.", v["oldest_critical_high_days"]), "/vulnerabilities")
        cur, prev = v["created_critical_high"]["current"], v["remediated_critical_high"]["current"]
        if cur > prev:
            add("warning", "ch_flow", m("En el periodo aparecieron {0} vulnerabilidades criticas o altas y se corrigieron {1}: la deuda crece.", cur, prev), "/vulnerabilities")
    if r:
        if r["false_closure_rate_pct"] is not None and r["false_closure_rate_pct"] >= 10:
            add("warning", "false_closure", m("El {0}% de los cierres declarados no paso la verificacion con un nuevo escaneo.", r["false_closure_rate_pct"]), "/vulnerabilities")
        if r["mttr_real_hours"] and r["mttr_declared_hours"] and r["mttr_real_hours"] - r["mttr_declared_hours"] >= 24 \
                and r["mttr_real_hours"] >= 1.5 * r["mttr_declared_hours"]:
            add("warning", "mttr_gap", m("El tiempo real de correccion ({0} h) es bastante mayor al declarado ({1} h).", round(r["mttr_real_hours"]), round(r["mttr_declared_hours"])), "/vulnerabilities")
        if r["remediated_unverified"]:
            add("info", "unverified", m("{0} correcciones declaradas todavia no tienen el cierre verificado.", r["remediated_unverified"]), "/vulnerabilities")
    c = s.get("compliance")
    if c and c.get("score_verified") is not None:
        if c["change"] is not None and c["change"] <= -5:
            add("warning", "compliance_drop", m("El puntaje de cumplimiento bajo {0} puntos respecto del periodo anterior.", abs(c["change"])), "/trust?tab=compliance")
        if c["score_verified"] < 50:
            add("warning", "compliance_low", m("El puntaje de cumplimiento verificado es {0} de 100.", c["score_verified"]), "/trust?tab=compliance")
    k = s.get("cases")
    if k and k["overdue"]:
        add("warning", "cases_overdue", m("{0} casos abiertos ya pasaron su plazo de atencion (SLA).", k["overdue"]), "/cases")
    e = s.get("exceptions")
    if e:
        if e["expiring_soon"]:
            add("warning", "exc_expiring", m("{0} excepciones de riesgo vencen en los proximos dias: hay que renovarlas o corregir.", e["expiring_soon"]), "/trust?tab=exceptions")
        if e["pending"]:
            add("info", "exc_pending", m("{0} pedidos de excepcion esperan una decision.", e["pending"]), "/trust?tab=exceptions")
        if e["active_critical_or_high"]:
            add("info", "exc_active", m("Hay {0} vulnerabilidades criticas o altas con el riesgo aceptado.", e["active_critical_or_high"]), "/trust?tab=exceptions")
    ve = s.get("vendors")
    if ve:
        if ve["high_or_critical_risk"]:
            add("warning", "vendor_risk", m("{0} proveedores tienen un riesgo alto o critico.", ve["high_or_critical_risk"]), "/trust?tab=vendors")
        if ve["without_assessment_critical_or_high"]:
            add("warning", "vendor_unassessed", m("{0} proveedores criticos o importantes no tienen una evaluacion vigente.", ve["without_assessment_critical_or_high"]), "/trust?tab=vendors")
    d = s.get("drills")
    if d:
        if not d["completed_total"]:
            add("warning", "no_drill", m("Todavia no se hizo ningun simulacro de respuesta a incidentes."), "/purple-team")
        elif d["days_since_last"] is not None and d["days_since_last"] > 180:
            add("warning", "old_drill", m("El ultimo simulacro fue hace {0} dias.", round(d["days_since_last"])), "/purple-team")
    cu = s.get("custody")
    if cu and not cu["ok"]:
        add("critical", "custody_broken", m("La cadena de custodia no pasa la verificacion: hay que revisarla antes de confiar en este informe."), "/trust?tab=custody")
    x = s.get("exposure")
    if x and x["total_score"] and x["unassigned_share_pct"] >= 50:
        add("info", "unassigned_units", m("El {0}% de la exposicion esta en activos sin unidad de negocio: asignala para ver quien es responsable.", round(x["unassigned_share_pct"])), "/assets")
    for name, src in (s.get("sources") or {}).items():
        if not src["ok"]:
            add("info", "source_down", m("No se pudo leer {0}: esa parte del informe queda sin datos.", name))
    order = {"critical": 0, "warning": 1, "info": 2}
    out.sort(key=lambda a: order[a["level"]])
    return out


def build_summary(facts: dict, now: datetime, days: int) -> dict:
    cur_start, prev_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    s: dict = {"generated_at": now.isoformat(), "days": days,
               "period": {"from": cur_start.isoformat(), "to": now.isoformat()},
               "previous_period": {"from": prev_start.isoformat(), "to": cur_start.isoformat()},
               "sources": {name: {"ok": bool(f.get("ok")), "error": f.get("error", "")} for name, f in facts["sources"].items()},
               "limits": LIMITS}
    ex = _data(facts, "executive")
    if ex:
        p, q = ex["period"], ex["previous"]
        o = ex["open"]
        s["vulnerabilities"] = {
            "open_total": o["total"], "by_severity": o["by_severity"], "critical_high": o["critical_high"], "kev": o["kev"],
            "oldest_critical_high_days": o["oldest_critical_high_days"], "accepted_risk": o["accepted_risk"],
            "created": delta(p["created"], q["created"]), "remediated": delta(p["remediated"], q["remediated"]),
            "created_critical_high": delta(p["created_critical_high"], q["created_critical_high"]),
            "remediated_critical_high": delta(p["remediated_critical_high"], q["remediated_critical_high"]),
        }
        s["exposure"] = exposure_by_unit(ex["by_asset"], _data(facts, "assets") or [])
        s["exposure"]["weights"] = ex["exposure_weights"]
        s["exposure"]["assets_known"] = _data(facts, "assets") is not None
    cl = _data(facts, "closure")
    if cl:
        real, declared = cl.get("mttr_real_hours"), cl.get("mttr_declared_hours")
        s["remediation"] = {
            "mttr_real_hours": real, "mttr_declared_hours": declared,
            "gap_hours": round(real - declared, 1) if real is not None and declared is not None else None,
            "false_closure_rate_pct": cl.get("false_closure_rate_pct"), "verified": cl["counts"].get("verified", 0),
            "failed": cl["counts"].get("failed", 0), "remediated_total": cl.get("remediated_total", 0),
            "remediated_unverified": cl.get("remediated_unverified", 0), "by_severity": cl.get("by_severity", {}),
        }
    comp = facts.get("compliance")
    if comp:
        sm = comp["summary"]
        hist = facts.get("compliance_history") or []
        before = [h for h in hist if h.get("score_verified") is not None and (_ts(h["created_at"]) or now) <= cur_start]
        prev_score = before[-1]["score_verified"] if before else None
        s["compliance"] = {"score_verified": sm["score_verified"], "score_total": sm["score_total"],
                           "verified_controls": sm["verified_controls"], "total_controls": sm["total_controls"],
                           "counts": sm["counts"], "previous_score_verified": prev_score,
                           "change": round(sm["score_verified"] - prev_score, 1) if sm["score_verified"] is not None and prev_score is not None else None}
    if facts.get("cases") is not None:
        s["cases"] = facts["cases"]
    if facts.get("exceptions") is not None:
        s["exceptions"] = facts["exceptions"]
    if facts.get("vendors") is not None:
        s["vendors"] = facts["vendors"]
    dr = _data(facts, "drills")
    if dr is not None:
        s["drills"] = {"completed_total": int(dr.get("completed_total") or 0), "days_since_last": dr.get("days_since_last"),
                       "last_score": dr.get("last_score"), "median_ack_seconds": dr.get("median_ack_seconds")}
    if facts.get("custody") is not None:
        s["custody"] = {"ok": bool(facts["custody"]["ok"]), "entries": facts["custody"]["entries"],
                        "head_hash": facts["custody"].get("head_hash", "")}
    attn = attention_list(s)
    s["attention"] = attn
    s["status"] = "attention" if any(a["level"] == "critical" for a in attn) else \
        "watch" if any(a["level"] == "warning" for a in attn) else "stable"
    return s


async def org_name(org: str | None) -> str:
    if not org:
        return ""
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            resp = await client.get(f"{URLS['auth']}/internal/organizations/{org}", headers=service_auth_headers("case-service", org))
        if resp.status_code < 300:
            return str(resp.json().get("name", ""))
    except (httpx.HTTPError, ValueError):
        pass
    return ""


async def collect(db: AsyncSession, org: str | None, days: int, now: datetime | None = None) -> dict:
    now = now or _now()
    async with httpx.AsyncClient(timeout=8.0) as client:
        keys = ["executive", "closure", "assets", "drills"]
        remote = await asyncio.gather(
            _get(client, org, "vuln", "/vulnerabilities/executive", {"days": days}),
            _get(client, org, "vuln", "/vulnerabilities/closure/stats"),
            _get(client, org, "asset", "/assets"),
            _get(client, org, "purple", "/drills/stats"),
        )
    facts: dict = dict(zip(keys, remote))
    names = {"executive": "vuln-service", "closure": "vuln-service", "assets": "asset-service", "drills": "purple-service"}
    sources: dict = {}
    for k, label in names.items():
        # un servicio caido se informa una sola vez
        if label not in sources or not facts[k]["ok"]:
            sources[label] = facts[k]
    local_errors: dict = {}

    async def local(key: str, label: str, coro):
        try:
            facts[key] = await coro
        except Exception as exc:
            facts[key] = None
            local_errors[label] = {"ok": False, "error": exc.__class__.__name__}

    await local("cases", "casos", _cases(db, org, now, days))
    await local("exceptions", "excepciones", _exceptions(db, org, now))
    await local("vendors", "proveedores", _vendors(db, org))
    await local("custody", "cadena de custodia", custody.verify(db, org))
    await local("compliance", "cumplimiento", compliance_service.evaluate(db, org))
    await local("compliance_history", "historial de cumplimiento", compliance_service.history(db, org, limit=400))
    sources.update(local_errors)
    # si el servicio de cumplimiento no pudo evaluar nada, `compliance` queda None y la seccion se omite
    facts["sources"] = sources
    return facts


async def _exceptions(db: AsyncSession, org: str | None, now: datetime) -> dict:
    return exception_service.summarize(await exception_service.list_rows(db, org), now)


async def _vendors(db: AsyncSession, org: str | None) -> dict:
    return vendor_service.summarize(await vendor_service.list_views(db, org))


async def summary(db: AsyncSession, org: str | None, days: int = 30, now: datetime | None = None) -> dict:
    days = clamp_days(days)
    now = now or _now()
    facts = await collect(db, org, days, now)
    s = build_summary(facts, now, days)
    s["organization"] = {"id": org or "", "name": await org_name(org)}
    return s


# ----------------------------- tendencia -----------------------------

def snapshot_data(s: dict) -> dict:
    v, r, c, e, ve, k = (s.get(x) or {} for x in ("vulnerabilities", "remediation", "compliance", "exceptions", "vendors", "cases"))
    return {"open_total": v.get("open_total"), "critical_high": v.get("critical_high"), "kev": v.get("kev"),
            "accepted_risk": v.get("accepted_risk"), "mttr_real_hours": r.get("mttr_real_hours"),
            "mttr_declared_hours": r.get("mttr_declared_hours"), "compliance": c.get("score_verified"),
            "exceptions_active": e.get("active"), "vendors_high_critical": ve.get("high_or_critical_risk"),
            "cases_open": k.get("open"), "cases_overdue": k.get("overdue"),
            "exposure": (s.get("exposure") or {}).get("total_score")}


async def take_snapshot(db: AsyncSession, org: str | None, s: dict | None = None) -> ExecutiveSnapshot:
    s = s or await summary(db, org, 30)
    today = _now().strftime("%Y-%m-%d")
    row = (await db.execute(select(ExecutiveSnapshot).where(ExecutiveSnapshot.organization_id == org,
                                                            ExecutiveSnapshot.day == today))).scalars().first()
    data = json.dumps(snapshot_data(s))
    if row is None:
        row = ExecutiveSnapshot(organization_id=org, day=today, data=data)
        db.add(row)
    else:
        row.data = data
    await db.flush()
    return row


async def trend(db: AsyncSession, org: str | None, days: int = 90) -> list[dict]:
    days = max(7, min(int(days), KEEP_DAYS))
    since = (_now() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = (await db.execute(select(ExecutiveSnapshot).where(ExecutiveSnapshot.organization_id == org, ExecutiveSnapshot.day >= since)
                             .order_by(ExecutiveSnapshot.day))).scalars().all()
    return [{"day": r.day, **json.loads(r.data or "{}")} for r in rows]


async def loop(session_factory, org_ids_fn) -> None:
    """Una foto por organizacion y por dia (UTC). Se revisa cada hora; si ya hay foto de hoy no hace nada."""
    if not SNAPSHOT_ENABLED:
        return
    await asyncio.sleep(180)
    while True:
        try:
            today = _now().strftime("%Y-%m-%d")
            for org in await org_ids_fn():
                async with session_factory() as db:
                    has = (await db.execute(select(ExecutiveSnapshot.id).where(ExecutiveSnapshot.organization_id == org,
                                                                               ExecutiveSnapshot.day == today))).first()
                    if has is None:
                        await take_snapshot(db, org)
                        await db.commit()
        except Exception as exc:
            logger.warning("fallo la foto diaria del tablero ejecutivo", extra={"error": str(exc)})
        await asyncio.sleep(3600)


# ----------------------------- informe firmado -----------------------------

def attestation_body(s: dict, trend_rows: list[dict]) -> dict:
    return {
        "organization": s.get("organization", {}), "generated_at": s["generated_at"], "days": s["days"],
        "period": s["period"], "previous_period": s["previous_period"], "status": s["status"],
        "vulnerabilities": s.get("vulnerabilities"), "remediation": s.get("remediation"), "exposure": s.get("exposure"),
        "compliance": s.get("compliance"), "cases": s.get("cases"), "exceptions": s.get("exceptions"),
        "vendors": s.get("vendors"), "drills": s.get("drills"), "custody": s.get("custody"),
        "attention": s["attention"], "sources": s["sources"], "trend": trend_rows, "limits": LIMITS,
        "meaning": ("Prueba que, en la fecha indicada, TERO calculo estos indicadores a partir de sus propios registros, y el estado de la "
                    "cadena de custodia en ese momento. No certifica que los controles funcionen ni el resultado de una auditoria."),
    }


async def make_report(db: AsyncSession, org: str | None, actor: str, days: int = 30) -> dict:
    s = await summary(db, org, days)
    await take_snapshot(db, org, s)
    rows = await trend(db, org, 180)
    doc = core.make_attestation("executive", org, attestation_body(s, rows))
    custody_payload = {"days": s["days"], "status": s["status"], "body_sha256": core.sha256_hex(core.canonical(doc["body"])),
                       "signature": doc["signature"][:32],
                       "critical_high_open": (s.get("vulnerabilities") or {}).get("critical_high")}
    await custody.append(db, org, "executive.report_signed", actor=actor, source="case-service", subject_type="executive",
                         subject_id="organization", payload=custody_payload)
    return doc
