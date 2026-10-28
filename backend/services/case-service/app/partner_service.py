"""Consola multicliente (MSSP): vista consolidada de los clientes de un partner y uso por cliente.

Reglas:
  * Solo se consolida a los clientes que auth-service dice que son hijos del partner de quien pregunta; la organizacion del
    partner sale del token, nunca de un parametro. Un token de alguien que "entro" a un cliente (claim partner_org_id) no sirve.
  * Cada cliente se calcula con las MISMAS reglas del tablero ejecutivo (estado estable / a vigilar / requiere atencion,
    exposicion ponderada, casos vencidos), en version liviana: no recalcula cumplimiento ni verifica la cadena de custodia
    (eso se hace al entrar al cliente). Si un cliente no se pudo leer, aparece como "sin datos" y arriba de la lista; nunca se
    completa con ceros ni se oculta.
  * Los calculos corren de a pocos a la vez y se guardan 60 segundos para que abrir la consola no sature los servicios."""
from __future__ import annotations

import asyncio
import csv
import io
import time
from datetime import datetime, timezone

import httpx

from backend.shared.database import SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.service_auth import service_auth_headers
from app import executive_service as ex
from app.compliance_evidence import URLS, _get

logger = configure_logging("partner")
CONCURRENCY = 4
CACHE_SECONDS = 60
_CACHE: dict[tuple[str, int], tuple[float, dict]] = {}
_RANK = {"attention": 0, "unknown": 1, "watch": 2, "stable": 3}


class PartnerError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


async def fetch_clients(partner_org: str) -> tuple[dict, list[dict]]:
    """(partner, clientes) segun auth-service. Levanta PartnerError si no es un partner o auth no responde."""
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"{URLS['auth']}/internal/partners/{partner_org}/clients",
                                    headers=service_auth_headers("case-service", partner_org))
    except httpx.HTTPError:
        raise PartnerError(502, "No pude consultar la lista de clientes. Proba de nuevo en un momento.")
    if resp.status_code == 404:
        raise PartnerError(403, "Tu organizacion no es un partner")
    if resp.status_code >= 300:
        raise PartnerError(502, "No pude consultar la lista de clientes. Proba de nuevo en un momento.")
    data = resp.json()
    return data["partner"], data["items"]


async def lean_summary(org: str, days: int, now: datetime) -> dict:
    """Resumen ejecutivo liviano de un cliente (sin cumplimiento ni verificacion de custodia)."""
    async with httpx.AsyncClient(timeout=8.0) as client:
        executive, closure, assets = await asyncio.gather(
            _get(client, org, "vuln", "/vulnerabilities/executive", {"days": days}),
            _get(client, org, "vuln", "/vulnerabilities/closure/stats"),
            _get(client, org, "asset", "/assets"),
        )
    facts: dict = {"executive": executive, "closure": closure, "assets": assets,
                   "sources": {"vuln-service": executive if not executive["ok"] else closure, "asset-service": assets}}
    async with SessionLocal() as db:
        for key, label, fn in (("cases", "casos", lambda: ex._cases(db, org, now, days)),
                               ("exceptions", "excepciones", lambda: ex._exceptions(db, org, now)),
                               ("vendors", "proveedores", lambda: ex._vendors(db, org))):
            try:
                facts[key] = await fn()
            except Exception as exc:  # una fuente local rota no tumba la consola
                facts[key] = None
                facts["sources"][label] = {"ok": False, "error": exc.__class__.__name__}
    s = ex.build_summary(facts, now, days)
    s["assets_count"] = len(ex._data(facts, "assets") or [])
    return s


def client_row(c: dict, s: dict | None, error: str = "") -> dict:
    """Una fila de la consola a partir de los datos del cliente y su resumen (None = no se pudo leer)."""
    row = {"id": c["id"], "name": c["name"], "is_active": c.get("is_active", True), "users": c.get("users", 0),
           "subscription_expires_at": c.get("subscription_expires_at")}
    if s is None or not c.get("is_active", True):
        row.update(status="unknown" if c.get("is_active", True) else "suspended", error=error)
        return row
    v, k, r, e, ve = (s.get(x) or {} for x in ("vulnerabilities", "cases", "remediation", "exceptions", "vendors"))
    levels = {"critical": 0, "warning": 0, "info": 0}
    for a in s.get("attention", []):
        levels[a["level"]] += 1
    # las fuentes caidas no son "atencion" del cliente: son un problema de lectura que se informa aparte
    down = [n for n, src in (s.get("sources") or {}).items() if not src["ok"]]
    row.update(
        status=s["status"], error="", sources_down=down, assets=s.get("assets_count", 0),
        exposure=(s.get("exposure") or {}).get("total_score"),
        open_total=v.get("open_total"), critical_high=v.get("critical_high"), kev=v.get("kev"),
        oldest_critical_high_days=v.get("oldest_critical_high_days"),
        cases_open=k.get("open"), cases_overdue=k.get("overdue"), cases_opened=(k.get("opened") or {}).get("current"),
        mttr_real_hours=r.get("mttr_real_hours"), exceptions_active=e.get("active"),
        vendors_high_critical=ve.get("high_or_critical_risk"),
        attention=levels, top_attention=[a for a in s.get("attention", []) if a["level"] != "info"][:3],
    )
    return row


def totals(rows: list[dict]) -> dict:
    live = [r for r in rows if r["status"] in ("attention", "watch", "stable")]
    def total(key):
        return sum(int(r.get(key) or 0) for r in live)
    return {
        "clients": len(rows), "active": sum(1 for r in rows if r["status"] != "suspended"),
        "by_status": {k: sum(1 for r in rows if r["status"] == k) for k in ("attention", "watch", "stable", "unknown", "suspended")},
        "critical_high": total("critical_high"), "kev": total("kev"), "open_total": total("open_total"),
        "cases_open": total("cases_open"), "cases_overdue": total("cases_overdue"), "assets": total("assets"),
        "users": sum(int(r.get("users") or 0) for r in rows),
    }


def sort_rows(rows: list[dict]) -> list[dict]:
    # suspendidos al final; el resto por estado y, dentro de cada estado, mayor exposicion primero
    return sorted(rows, key=lambda r: (r["status"] == "suspended", _RANK.get(r["status"], 9), -(r.get("exposure") or 0), r["name"].lower()))


async def _cached_summary(org: str, days: int, now: datetime, use_cache: bool) -> dict:
    """Resumen liviano de un cliente, guardado 60 segundos (la lista de clientes, en cambio, se pide siempre: un cliente nuevo o
    suspendido se ve al instante)."""
    key = (org, days)
    hit = _CACHE.get(key)
    if use_cache and hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    s = await lean_summary(org, days, now)
    _CACHE[key] = (time.monotonic(), s)
    if len(_CACHE) > 2000:
        _CACHE.pop(next(iter(_CACHE)))
    return s


async def overview(partner_org: str, days: int, now: datetime | None = None, use_cache: bool = True) -> dict:
    days = ex.clamp_days(days)
    now = now or datetime.now(timezone.utc)
    partner, clients = await fetch_clients(partner_org)
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(c: dict) -> dict:
        if not c.get("is_active", True):
            return client_row(c, None)
        async with sem:
            try:
                return client_row(c, await _cached_summary(c["id"], days, now, use_cache))
            except Exception as exc:
                logger.warning("no pude resumir a un cliente", extra={"client": c["id"], "error": exc.__class__.__name__})
                return client_row(c, None, exc.__class__.__name__)

    rows = sort_rows(await asyncio.gather(*(one(c) for c in clients)))
    return {"generated_at": now.isoformat(), "days": days, "partner": partner, "totals": totals(rows), "clients": rows}


def _safe(value) -> str:
    """Evita que una planilla interprete un nombre como formula (=, +, -, @)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


USAGE_COLUMNS = [
    ("name", "Cliente"), ("status", "Estado"), ("users", "Usuarios activos"), ("assets", "Activos"),
    ("open_total", "Vulnerabilidades abiertas"), ("critical_high", "Criticas y altas abiertas"), ("kev", "Explotadas activamente"),
    ("cases_open", "Casos abiertos"), ("cases_opened", "Casos abiertos en el periodo"), ("cases_overdue", "Casos vencidos"),
    ("mttr_real_hours", "Tiempo real de correccion (h)"), ("subscription_expires_at", "Suscripcion vence"),
]
STATUS_ES = {"attention": "Requiere atencion", "watch": "A vigilar", "stable": "Estable", "unknown": "Sin datos", "suspended": "Suspendido"}


def usage_csv(data: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow([f"Uso por cliente - {data['partner']['name']} - ultimos {data['days']} dias - generado {data['generated_at'][:19]}Z"])
    w.writerow([label for _, label in USAGE_COLUMNS])
    for r in data["clients"]:
        w.writerow([_safe(STATUS_ES.get(r[k], r[k])) if k == "status" else _safe(r.get(k)) for k, _ in USAGE_COLUMNS])
    t = data["totals"]
    w.writerow(["TOTAL", f"{t['clients']} clientes", t["users"], t["assets"], t["open_total"], t["critical_high"], t["kev"],
                t["cases_open"], "", t["cases_overdue"], "", ""])
    return "﻿" + out.getvalue()
