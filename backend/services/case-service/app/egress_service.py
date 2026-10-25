"""Logica de la prueba de soberania: recibe los informes de los servicios, clasifica los destinos,
hace la prueba de conectividad y arma el estado y el atestado firmado.

Veredictos (de mas a menos fuerte):
  isolated_verified   -- todos los servicios esperados informan modo aislado Y la prueba de red no pudo salir.
  isolated_unverified -- todos informan modo aislado pero la red no esta confirmada (sin prueba o la prueba salio).
  controlled          -- hay salidas, pero todas son destinos conocidos (catalogados o configurados).
  unexpected          -- salio algo a un destino externo que no esta catalogado ni lo pudo configurar un usuario.
  no_data             -- todavia no informo ningun servicio."""
from __future__ import annotations

import asyncio
import json
import os
import socket
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from app import custody_service as custody
from app.egress_catalog import CATALOG, EXPECTED_SERVICES, USER_CONFIGURABLE, classify
from app.egress_models import EgressDestination, EgressProbe, EgressService

STALE_SECONDS = 5 * 60
RECENT_DAYS = 30
PROBE_TIMEOUT = 3.0
DEFAULT_PROBE_TARGETS = [("1.1.1.1", 443, "tcp"), ("8.8.8.8", 53, "tcp"), ("9.9.9.9", 443, "tcp"), ("example.com", 443, "dns")]
MAX_DEST_PER_REPORT = 500

Connector = Callable[[str, int, str, float], Awaitable[tuple[bool, str]]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _parse(ts: str | None) -> datetime:
    try:
        return _aware(datetime.fromisoformat(ts)) or _now()  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return _now()


def _json_list(text: str) -> list:
    try:
        value = json.loads(text or "[]")
        return value if isinstance(value, list) else []
    except ValueError:
        return []


# --- Informes de los servicios ---------------------------------------------------------------------

async def ingest_report(db: AsyncSession, report: dict) -> dict:
    """Guarda el informe de un servicio. Devuelve {"mode_changed": (antes, ahora) | None}."""
    service = str(report.get("service", ""))[:60]
    now = _now()
    row = await db.get(EgressService, service)
    isolated = bool(report.get("isolated", False))
    changed = None
    if row is None:
        row = EgressService(service=service)
        db.add(row)
    elif row.isolated != isolated:
        changed = (row.isolated, isolated)
    row.instance = str(report.get("instance", ""))[:120]
    row.isolated = isolated
    row.allowlist = json.dumps(sorted(str(h)[:255] for h in (report.get("allowlist") or []))[:50])
    row.boot = str(report.get("boot", ""))[:40]
    row.last_seen = now

    for d in (report.get("destinations") or [])[:MAX_DEST_PER_REPORT]:
        host = str(d.get("host", "")).strip().lower()[:255]
        kind = str(d.get("kind", "http"))[:20]
        if not host:
            continue
        dest = (await db.execute(select(EgressDestination).where(
            EgressDestination.service == service, EgressDestination.host == host, EgressDestination.kind == kind
        ))).scalars().first()
        first, last = _parse(d.get("first_seen")), _parse(d.get("last_seen"))
        purposes = [str(p)[:120] for p in (d.get("purposes") or [])][:5]
        if dest is None:
            dest = EgressDestination(service=service, host=host, kind=kind, count=0, blocked=0, purposes="[]",
                                     first_seen=first, last_seen=last)
            db.add(dest)
        dest.count = (dest.count or 0) + max(0, int(d.get("count", 0)))
        dest.blocked = (dest.blocked or 0) + max(0, int(d.get("blocked", 0)))
        dest.first_seen = min(_aware(dest.first_seen) or first, first)
        dest.last_seen = max(_aware(dest.last_seen) or last, last)
        merged = _json_list(dest.purposes)
        for p in purposes:
            if p not in merged and len(merged) < 5:
                merged.append(p)
        dest.purposes = json.dumps(merged)
    await db.flush()
    return {"mode_changed": changed}


async def record_mode_change(db: AsyncSession, org_ids: list[str], service: str, before: bool, after: bool) -> None:
    for org in org_ids:
        await custody.append(
            db, org, "sovereignty.mode_changed", actor="system", source="case-service", subject_type="sovereignty",
            subject_id=service, refs=[], payload={"service": service, "isolated_before": before, "isolated_after": after})


# --- Prueba de conectividad --------------------------------------------------------------------------

def probe_targets() -> list[tuple[str, int, str]]:
    raw = os.getenv("TERO_PROBE_TARGETS", "").strip()
    if not raw:
        return list(DEFAULT_PROBE_TARGETS)
    out = []
    for part in raw.split(","):
        host, _, port = part.strip().partition(":")
        if host:
            out.append((host, int(port) if port.isdigit() else 443, "tcp"))
    return out or list(DEFAULT_PROBE_TARGETS)


async def real_connector(host: str, port: int, kind: str, timeout: float) -> tuple[bool, str]:
    """Intenta salir de verdad: conexion TCP (o resolucion DNS). No envia ningun dato."""
    try:
        if kind == "dns":
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout)
            return True, "el nombre se resolvio"
        _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
        return True, "conexion establecida"
    except asyncio.TimeoutError:
        return False, "sin respuesta (tiempo agotado)"
    except OSError as exc:
        return False, "rechazada o sin ruta"


async def run_probe(db: AsyncSession, actor: str, org_id: str | None, connector: Connector | None = None) -> dict:
    connector = connector or real_connector
    targets = probe_targets()
    outcomes = await asyncio.gather(*(connector(h, p, k, PROBE_TIMEOUT) for h, p, k in targets))
    results = [{"target": f"{h}:{p}", "kind": k, "reachable": ok, "detail": detail, "informational": k == "dns"}
               for (h, p, k), (ok, detail) in zip(targets, outcomes)]
    counted = [r for r in results if not r["informational"]]
    reachable = sum(1 for r in counted if r["reachable"])
    probe = EgressProbe(actor=actor[:255], reachable=reachable, total=len(counted), results=json.dumps(results))
    db.add(probe)
    await db.flush()
    st = await status(db)
    await custody.append(
        db, org_id, "sovereignty.probe", actor=actor, source="case-service", subject_type="sovereignty",
        subject_id="installation", refs=[],
        payload={"reachable": reachable, "total": len(counted), "targets": [r["target"] for r in results],
                 "verdict": st["verdict"], "isolated_services": st["summary"]["isolated_services"]})
    return {**probe_to_dict(probe), "verdict": st["verdict"]}


def probe_to_dict(p: EgressProbe) -> dict:
    return {"id": p.id, "created_at": (_aware(p.created_at) or _now()).isoformat(), "actor": p.actor,
            "reachable": p.reachable, "total": p.total, "results": _json_list(p.results)}


async def last_probe(db: AsyncSession) -> EgressProbe | None:
    return (await db.execute(select(EgressProbe).order_by(EgressProbe.created_at.desc()).limit(1))).scalars().first()


# --- Estado ------------------------------------------------------------------------------------------

async def status(db: AsyncSession) -> dict:
    now = _now()
    services = (await db.execute(select(EgressService))).scalars().all()
    by_name = {s.service: s for s in services}
    fresh = {n: s for n, s in by_name.items() if (now - (_aware(s.last_seen) or now)).total_seconds() <= STALE_SECONDS}
    missing = [n for n in EXPECTED_SERVICES if n not in fresh]

    since = now - timedelta(days=RECENT_DAYS)
    dests = (await db.execute(select(EgressDestination).order_by(EgressDestination.last_seen.desc()))).scalars().all()
    out_dests, unknown = [], []
    for d in dests:
        cls, entry = classify(d.service, d.host)
        item = {
            "service": d.service, "host": d.host, "kind": d.kind, "count": d.count, "blocked": d.blocked,
            "first_seen": (_aware(d.first_seen) or now).isoformat(), "last_seen": (_aware(d.last_seen) or now).isoformat(),
            "classification": cls, "purposes": _json_list(d.purposes),
            "catalog": ({k: entry[k] for k in ("id", "category", "purpose", "sends", "optional", "offline")} if entry else None),
            "recent": (_aware(d.last_seen) or now) >= since,
        }
        out_dests.append(item)
        if cls == "no_catalogado" and item["recent"] and d.count - d.blocked > 0:
            unknown.append(item)

    probe = await last_probe(db)
    all_isolated = bool(fresh) and not missing and all(s.isolated for s in fresh.values())
    net_closed = probe is not None and probe.reachable == 0

    notes: list[dict] = []
    if not services:
        verdict = "no_data"
    elif unknown:
        verdict = "unexpected"
        notes.append(note("Hay salidas a destinos que no estan catalogados: revisalos en la tabla."))
    elif all_isolated and net_closed:
        verdict = "isolated_verified"
    elif all_isolated:
        verdict = "isolated_unverified"
        notes.append(note("Falta la prueba de red.") if probe is None else
                     note("La prueba de red logro salir a internet: el modo aislado de la aplicacion no alcanza, falta aislar la red."))
    else:
        verdict = "controlled"
        if any(s.isolated for s in fresh.values()):
            notes.append(note("El modo aislado esta activo solo en algunos servicios."))
    if missing and services:
        notes.append(note("Sin informes recientes de: {0}.", ", ".join(missing)))
    exceptions = network_exceptions()
    if exceptions and verdict.startswith("isolated"):
        notes.append(note("El aislamiento de red no cubre {0} (necesita llegar a tu red local); alli rige solo el modo aislado de la aplicacion.",
                          ", ".join(exceptions)))

    return {
        "verdict": verdict, "notes": notes,
        "summary": {
            "services_expected": len(EXPECTED_SERVICES), "services_reporting": len(fresh), "services_missing": missing,
            "isolated_services": sum(1 for s in fresh.values() if s.isolated),
            "external_destinations": sum(1 for d in out_dests if d["recent"]), "unknown_destinations": len(unknown),
            "blocked_attempts": sum(d["blocked"] for d in out_dests),
        },
        "services": [{"service": n, "isolated": s.isolated, "instance": s.instance, "allowlist": _json_list(s.allowlist),
                      "last_seen": (_aware(s.last_seen) or now).isoformat(), "reporting": n in fresh,
                      "configurable": USER_CONFIGURABLE.get(n, "")}
                     for n, s in sorted(by_name.items())],
        "destinations": out_dests,
        "probe": probe_to_dict(probe) if probe else None,
        "network_exceptions": exceptions,
    }


def network_exceptions() -> list[str]:
    """Servicios que, por diseno del compose aislado, conservan salida de red (ej. scan-service, que necesita
    llegar a tu red local). Los declara el despliegue en TERO_NETWORK_EXCEPTIONS."""
    return sorted({x.strip() for x in os.getenv("TERO_NETWORK_EXCEPTIONS", "").split(",") if x.strip()})


def catalog_view() -> list[dict]:
    return [dict(e) for e in CATALOG]


def note(text: str, *args) -> dict:
    """Aviso para la pantalla: texto con {0}, {1}... y sus valores (asi el frontend lo traduce con los valores adentro)."""
    return {"text": text, "args": [str(a) for a in args]}


LIMITS = [
    "Solo se ve lo que sale por la aplicacion (HTTP, SMTP, AWS, git). Programas externos que un servicio lance como proceso "
    "(trivy, nuclei) no se miden desde adentro: por eso la prueba de red es la que manda.",
    "La prueba de red se hace desde el contenedor de case-service; si otros servicios estan en redes distintas, probalos aparte.",
    "El atestado prueba lo que TERO observo hasta el momento de firmarlo, no lo que ocurra despues.",
]


async def attestation_body(db: AsyncSession) -> dict:
    st = await status(db)
    return {
        "verdict": st["verdict"], "notes": st["notes"], "summary": st["summary"],
        "services": [{k: s[k] for k in ("service", "isolated", "last_seen", "reporting")} for s in st["services"]],
        "destinations": [{k: d[k] for k in ("service", "host", "kind", "count", "blocked", "classification", "last_seen")}
                         for d in st["destinations"] if d["recent"]],
        "probe": ({"created_at": st["probe"]["created_at"], "reachable": st["probe"]["reachable"], "total": st["probe"]["total"],
                   "results": st["probe"]["results"]} if st["probe"] else None),
        "network_exceptions": st["network_exceptions"], "limits": LIMITS,
    }


async def make_attestation(db: AsyncSession, org_id: str | None, actor: str) -> dict:
    doc = core.make_attestation("sovereignty", org_id, await attestation_body(db))
    await custody.append(
        db, org_id, "sovereignty.attestation", actor=actor, source="case-service", subject_type="sovereignty",
        subject_id="installation", refs=[],
        payload={"verdict": doc["body"]["verdict"], "body_sha256": core.sha256_hex(core.canonical(doc["body"])),
                 "signature": doc["signature"][:32]})
    return doc
