"""Simulacros medibles de respuesta a incidentes.

Que hace: pone UN evento sintetico, claramente rotulado "[SIMULACRO TERO]", en el SIEM de la organizacion. El
SIEM lo detecta con una regla propia del simulacro y genera una alerta (marcada como simulacro). Desde ahi se
MIDE cuanto tarda una persona en reconocer la alerta y en cerrarla dejando una nota, y se da un puntaje de
preparacion.

Que NO hace (a proposito):
  * No ejecuta tecnicas de ataque ni toca ningun sistema: solo agrega una linea de log inofensiva.
  * No dispara playbooks de respuesta automatica (bloqueo de IP, aislamiento de host...): siem-service omite SOAR y
    el enriquecimiento externo para las alertas de simulacro (regla con la etiqueta `tero-drill`).
  * No prueba las reglas reales de la organizacion: prueba que el camino evento -> alerta funciona y, sobre todo,
    que las PERSONAS responden a tiempo. Para medir cobertura de tecnicas esta el analisis de cobertura ATT&CK.

De donde salen los tiempos: la creacion de la alerta y los cambios de estado salen de la cadena de custodia
(eventos alert.created / alert.status_changed con su hora), que no se puede alterar despues."""
from __future__ import annotations

import asyncio
import os
import statistics
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody
from backend.shared.ingest_auth import ingest_headers
from backend.shared.logging import configure_logging
from backend.shared.service_auth import service_auth_headers
from app.models import PurpleDrill

logger = configure_logging("purple-drills")

SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")
CASE_SERVICE_URL = os.getenv("CASE_SERVICE_URL", "http://case-service:8000")
SOAR_SERVICE_URL = os.getenv("SOAR_SERVICE_URL", "http://soar-service:8000")
DRILL_TAG = "tero-drill"
SERVICE = "purple-service"
EXPIRE_HOURS = float(os.getenv("DRILL_EXPIRE_HOURS", "24"))
POLL_SECONDS = float(os.getenv("DRILL_POLL_SECONDS", "20"))
MIN_NOTE_CHARS = 10
RUNNING, COMPLETED, EXPIRED, CANCELLED = "running", "completed", "expired", "cancelled"

SCENARIOS: dict[str, dict] = {
    "phishing": {
        "title": "Inicio de sesion sospechoso tras un correo de phishing", "severity": "high",
        "narrative": "Un usuario hizo clic en un enlace de un correo falso y despues se registro un inicio de sesion desde un lugar inusual.",
        "steps": ["Reconocer la alerta", "Confirmar con el usuario si fue el", "Forzar el cambio de contrasena y cerrar sesiones",
                  "Revisar si hubo accesos a datos", "Cerrar la alerta con una nota de lo hecho"],
    },
    "ransomware": {
        "title": "Cifrado masivo de archivos en un servidor", "severity": "critical",
        "narrative": "Un servidor de archivos muestra cientos de archivos renombrados con una extension desconocida en pocos minutos.",
        "steps": ["Reconocer la alerta", "Aislar el servidor de la red", "Avisar al responsable y a la direccion",
                  "Verificar el estado de las copias de respaldo", "Cerrar la alerta con una nota de lo hecho"],
    },
    "fuerza_bruta": {
        "title": "Intentos repetidos de acceso a un servicio expuesto", "severity": "medium",
        "narrative": "Un servicio accesible desde internet recibio decenas de intentos de inicio de sesion fallidos en un minuto.",
        "steps": ["Reconocer la alerta", "Identificar el origen de los intentos", "Bloquear el origen si corresponde",
                  "Confirmar que ninguna cuenta fue vulnerada", "Cerrar la alerta con una nota de lo hecho"],
    },
    "exfiltracion": {
        "title": "Transferencia inusual de datos hacia un destino externo", "severity": "high",
        "narrative": "Un equipo envio un volumen de datos muy superior al normal hacia una direccion de internet desconocida.",
        "steps": ["Reconocer la alerta", "Identificar el equipo y el usuario", "Cortar la conexion si sigue activa",
                  "Determinar que datos pudieron salir", "Cerrar la alerta con una nota de lo hecho"],
    },
}

# Umbrales del puntaje (segundos). Estan a la vista en la pantalla: nadie tiene que adivinar como se puntua.
ACK_BANDS = [(15 * 60, 40), (60 * 60, 30), (4 * 3600, 20)]      # reconocer la alerta: hasta 15 min / 1 h / 4 h; despues 10
CLOSE_BANDS = [(4 * 3600, 30), (24 * 3600, 20)]                  # cerrar con nota: hasta 4 h / 24 h; despues 10
ACK_FLOOR, CLOSE_FLOOR = 10, 10                                  # reconocio / cerro, pero fuera de todos los plazos
POINTS = {"detect": 30, "ack": 40, "close": 30}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse(ts) -> datetime | None:
    if not ts:
        return None
    try:
        return _aware(datetime.fromisoformat(str(ts).replace("Z", "+00:00")))
    except ValueError:
        return None


def _secs(a: datetime | None, b: datetime | None) -> float | None:
    if a is None or b is None:
        return None
    return round(max(0.0, (b - a).total_seconds()), 1)


def rating(score: int | None) -> str:
    if score is None:
        return "sin_datos"
    return "preparado" if score >= 80 else "parcial" if score >= 50 else "insuficiente"


def _band(seconds: float | None, bands: list[tuple[int, int]], floor: int) -> int:
    if seconds is None:
        return 0
    for limit, points in bands:
        if seconds <= limit:
            return points
    return floor


def score(detected: bool, ack_s: float | None, closed_s: float | None, note_ok: bool) -> dict:
    """Puntaje 0-100 y el detalle de cada parte (para mostrarlo y firmarlo)."""
    detect = POINTS["detect"] if detected else 0
    ack = _band(ack_s, ACK_BANDS, ACK_FLOOR) if detected else 0
    if detected and closed_s is not None:
        full = _band(closed_s, CLOSE_BANDS, CLOSE_FLOOR)
        close = full if note_ok else full // 2
    else:
        close = 0
    parts = [
        {"key": "detect", "points": detect, "max": POINTS["detect"]},
        {"key": "ack", "points": ack, "max": POINTS["ack"]},
        {"key": "close", "points": close, "max": POINTS["close"]},
    ]
    return {"score": detect + ack + close, "parts": parts}


# ----------------------------- clientes (se reemplazan en los tests) -----------------------------

class DrillError(Exception):
    pass


class Clients:
    """Habla con siem-service (regla, evento, alertas), case-service (hora de los cambios de estado) y soar-service
    (solo para informar cuantos playbooks habilitados responderian; nunca los ejecuta)."""

    def _h(self, org: str | None) -> dict:
        return service_auth_headers(SERVICE, org)

    async def _call(self, method: str, url: str, org: str | None, **kw):
        headers = {**self._h(org), **kw.pop("headers", {})}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.request(method, url, headers=headers, **kw)
        except httpx.HTTPError as exc:
            raise DrillError(f"no se pudo conectar ({exc.__class__.__name__})")
        if resp.status_code >= 300:
            raise DrillError(f"HTTP {resp.status_code}")
        return resp.json() if resp.content else None

    async def ensure_rule(self, org: str | None, scenario: str) -> str:
        spec = SCENARIOS[scenario]
        name = f"[SIMULACRO] {spec['title']}"
        rules = await self._call("GET", f"{SIEM_SERVICE_URL}/rules", org)
        for r in rules or []:
            if r.get("name") == name:
                if not r.get("is_enabled", True):
                    await self._call("PATCH", f"{SIEM_SERVICE_URL}/rules/{r['id']}", org, json={"is_enabled": True})
                return r["id"]
        created = await self._call("POST", f"{SIEM_SERVICE_URL}/rules", org, json={
            "name": name, "description": "Regla propia de los simulacros de TERO. Solo detecta el evento sintetico del simulacro.",
            "severity": spec["severity"], "tags": [DRILL_TAG, f"{DRILL_TAG}:{scenario}"], "is_enabled": True,
            "detection": {"selection": {"event.action": f"tero_drill:{scenario}"}, "condition": "selection"}})
        return created["id"]

    async def ingest(self, org: str | None, event: dict) -> int:
        out = await self._call("POST", f"{SIEM_SERVICE_URL}/logs/ingest", org, headers=ingest_headers(),
                               json={"organization_id": org, "events": [event]})
        return int((out or {}).get("alerts_created", 0))

    async def alerts(self, org: str | None, rule_id: str) -> list[dict]:
        return await self._call("GET", f"{SIEM_SERVICE_URL}/alerts", org, params={"rule_id": rule_id}) or []

    async def status_changes(self, org: str | None, alert_id: str) -> list[dict]:
        out = await self._call("GET", f"{CASE_SERVICE_URL}/custody/entries", org,
                               params={"subject_id": alert_id, "event_type": "alert.status_changed", "limit": 200})
        return (out or {}).get("items", [])

    async def playbooks(self, org: str | None) -> list[dict]:
        return await self._call("GET", f"{SOAR_SERVICE_URL}/playbooks", org) or []


def get_clients() -> Clients:
    return Clients()


# ----------------------------- ciclo de vida -----------------------------

def _event(drill_id: str, scenario: str) -> dict:
    spec = SCENARIOS[scenario]
    return {
        "host": "simulacro-tero", "user": "simulacro", "source_ip": "192.0.2.10",  # 192.0.2.0/24: rango reservado para documentacion
        "event_action": f"tero_drill:{scenario}", "event_category": "drill", "event_outcome": "simulated",
        "message": f"[SIMULACRO TERO] {spec['title']}. Esto es un ejercicio: no hay ningun incidente real.",
        "source_type": "tero-drill", "severity": spec["severity"], "raw": drill_id,
    }


def would_respond(playbooks: list[dict], severity: str) -> int:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return sum(1 for p in playbooks if p.get("is_enabled") and rank.get(severity, 0) >= rank.get(p.get("min_severity", "low"), 0))


async def running_drill(db: AsyncSession, org: str | None) -> PurpleDrill | None:
    return (await db.execute(select(PurpleDrill).where(PurpleDrill.organization_id == org, PurpleDrill.status == RUNNING))).scalars().first()


async def start(db: AsyncSession, org: str | None, actor: str, scenario: str, clients: Clients | None = None) -> PurpleDrill:
    if scenario not in SCENARIOS:
        raise DrillError("Escenario desconocido")
    if await running_drill(db, org) is not None:
        raise DrillError("Ya hay un simulacro en curso: terminalo o cancelalo antes de empezar otro")
    clients = clients or get_clients()
    spec = SCENARIOS[scenario]
    drill = PurpleDrill(organization_id=org, scenario=scenario, title=spec["title"], severity=spec["severity"],
                        started_by=actor[:255], status=RUNNING)
    db.add(drill)
    await db.flush()
    try:
        rule_id = await clients.ensure_rule(org, scenario)
        drill.rule_id = rule_id
        drill.injected_at = _now()
        created = await clients.ingest(org, _event(drill.id, scenario))
    except DrillError as exc:
        raise DrillError(f"No se pudo poner el evento de simulacro en el SIEM: {exc}")
    drill.detected = created > 0
    try:
        drill.playbooks_would_respond = would_respond(await clients.playbooks(org), spec["severity"])
    except DrillError:
        drill.playbooks_would_respond = None
    await db.flush()
    await custody.record_event(
        "drill.started", service=SERVICE, organization_id=org, actor=actor, subject_type="drill", subject_id=drill.id,
        refs=[f"drill:{drill.id}"], payload={"scenario": scenario, "title": spec["title"], "severity": spec["severity"],
                                              "injected_at": drill.injected_at.isoformat(), "alert_created": drill.detected})
    return drill


async def step(db: AsyncSession, drill: PurpleDrill, clients: Clients | None = None, now: datetime | None = None) -> str:
    """Mira el SIEM: busca la alerta del simulacro, los cambios de estado y decide si ya termino o vencio."""
    if drill.status != RUNNING:
        return drill.status
    clients = clients or get_clients()
    now = now or _now()
    org = drill.organization_id
    try:
        if drill.alert_id is None:
            for a in await clients.alerts(org, drill.rule_id or ""):
                if str((a.get("matched_event") or {}).get("sentinelops", {}).get("raw", "")) == drill.id:
                    drill.alert_id = a["id"]
                    drill.alert_created_at = _parse(a.get("created_at"))
                    drill.detected = True
                    break
        if drill.alert_id:
            for e in sorted(await clients.status_changes(org, drill.alert_id), key=lambda x: x.get("seq", 0)):
                p, ts = e.get("payload") or {}, _parse(e.get("ts"))
                to = p.get("to")
                if to in ("acknowledged", "closed") and drill.acked_at is None:
                    drill.acked_at, drill.acked_by = ts, str(e.get("actor", ""))[:255]
                if to == "closed":
                    drill.closed_at, drill.closed_by = ts, str(e.get("actor", ""))[:255]
                    drill.close_note_chars = len(str(p.get("notes", "")).strip())
    except DrillError as exc:
        drill.last_error = str(exc)[:200]
        return drill.status
    drill.last_error = ""
    if drill.closed_at is not None:
        await finalize(db, drill, COMPLETED, now)
    elif now - _aware(drill.injected_at or drill.started_at) > timedelta(hours=EXPIRE_HOURS):
        await finalize(db, drill, EXPIRED, now)
    return drill.status


def results(drill: PurpleDrill) -> dict:
    base = _aware(drill.alert_created_at) or _aware(drill.injected_at)
    ack_s = _secs(base, _aware(drill.acked_at))
    closed_s = _secs(base, _aware(drill.closed_at))
    detect_s = _secs(_aware(drill.injected_at), _aware(drill.alert_created_at))
    sc = score(bool(drill.detected), ack_s, closed_s, (drill.close_note_chars or 0) >= MIN_NOTE_CHARS)
    return {"detected": bool(drill.detected), "detect_seconds": detect_s, "ack_seconds": ack_s, "close_seconds": closed_s,
            "acked_by": drill.acked_by, "closed_by": drill.closed_by, "note_ok": (drill.close_note_chars or 0) >= MIN_NOTE_CHARS,
            "playbooks_would_respond": drill.playbooks_would_respond, **sc, "rating": rating(sc["score"])}


async def finalize(db: AsyncSession, drill: PurpleDrill, status: str, now: datetime | None = None) -> None:
    drill.status = status
    drill.completed_at = now or _now()
    res = results(drill)
    drill.score = res["score"]
    drill.result = res
    await db.flush()
    await custody.record_event(
        "drill.completed" if status != CANCELLED else "drill.cancelled", service=SERVICE, organization_id=drill.organization_id,
        actor=drill.closed_by or drill.started_by, subject_type="drill", subject_id=drill.id,
        refs=[f"drill:{drill.id}"] + ([f"alert:{drill.alert_id}"] if drill.alert_id else []),
        payload={"scenario": drill.scenario, "title": drill.title, "severity": drill.severity, "status": status,
                 "injected_at": _aware(drill.injected_at).isoformat() if drill.injected_at else "",
                 "alert_id": drill.alert_id or "", "thresholds": {"ack": ACK_BANDS, "close": CLOSE_BANDS, "points": POINTS, "floors": {"ack": ACK_FLOOR, "close": CLOSE_FLOOR},
                                                                  "min_note_chars": MIN_NOTE_CHARS, "expire_hours": EXPIRE_HOURS},
                 **{k: res[k] for k in ("detected", "detect_seconds", "ack_seconds", "close_seconds", "acked_by", "closed_by",
                                        "note_ok", "playbooks_would_respond", "score", "parts", "rating")}})


async def cancel(db: AsyncSession, drill: PurpleDrill, actor: str) -> None:
    if drill.status == RUNNING:
        drill.closed_by = actor[:255]
        await finalize(db, drill, CANCELLED)


def view(drill: PurpleDrill) -> dict:
    spec = SCENARIOS.get(drill.scenario, {})
    return {
        "id": drill.id, "scenario": drill.scenario, "title": drill.title, "severity": drill.severity, "status": drill.status,
        "narrative": spec.get("narrative", ""), "steps": spec.get("steps", []),
        "started_by": drill.started_by, "started_at": _aware(drill.started_at).isoformat() if drill.started_at else None,
        "injected_at": _aware(drill.injected_at).isoformat() if drill.injected_at else None,
        "alert_id": drill.alert_id, "acked_at": _aware(drill.acked_at).isoformat() if drill.acked_at else None,
        "closed_at": _aware(drill.closed_at).isoformat() if drill.closed_at else None,
        "completed_at": _aware(drill.completed_at).isoformat() if drill.completed_at else None,
        "score": drill.score, "result": drill.result if drill.status != RUNNING and drill.result else results(drill),
        "last_error": drill.last_error, "expires_at": (_aware(drill.injected_at or drill.started_at) + timedelta(hours=EXPIRE_HOURS)).isoformat()
        if (drill.injected_at or drill.started_at) else None,
    }


async def stats(db: AsyncSession, org: str | None, now: datetime | None = None) -> dict:
    now = now or _now()
    rows = (await db.execute(select(PurpleDrill).where(PurpleDrill.organization_id == org, PurpleDrill.status.in_([COMPLETED, EXPIRED]))
                             .order_by(PurpleDrill.completed_at.desc()))).scalars().all()
    running = await running_drill(db, org)
    last = rows[0] if rows else None
    recent = rows[:5]
    scores = [r.score for r in recent if r.score is not None]
    avg = round(sum(scores) / len(scores), 1) if scores else None
    acks = [r.result.get("ack_seconds") for r in recent if r.result and r.result.get("ack_seconds") is not None]
    closes = [r.result.get("close_seconds") for r in recent if r.result and r.result.get("close_seconds") is not None]
    days = round((now - _aware(last.completed_at)).total_seconds() / 86400, 1) if last and last.completed_at else None
    return {
        "completed_total": len(rows), "running": running.id if running else None,
        "last_completed_at": _aware(last.completed_at).isoformat() if last else None, "days_since_last": days,
        "last_score": last.score if last else None, "average_score_last5": avg, "rating": rating(round(avg) if avg is not None else None),
        "median_ack_seconds": round(statistics.median(acks), 1) if acks else None,
        "median_close_seconds": round(statistics.median(closes), 1) if closes else None,
        "completed_last_90_days": sum(1 for r in rows if r.completed_at and now - _aware(r.completed_at) <= timedelta(days=90)),
        "scenarios_done": sorted({r.scenario for r in rows}),
        "history": [{"id": r.id, "scenario": r.scenario, "title": r.title, "score": r.score, "completed_at": _aware(r.completed_at).isoformat()}
                    for r in reversed(rows[:12])],
    }


async def process_running(session_factory, clients: Clients | None = None) -> int:
    touched = 0
    async with session_factory() as db:
        for drill in (await db.execute(select(PurpleDrill).where(PurpleDrill.status == RUNNING))).scalars().all():
            try:
                await step(db, drill, clients)
                touched += 1
            except Exception as exc:  # un simulacro roto no frena a los demas
                logger.warning("fallo el seguimiento de un simulacro", extra={"drill_id": drill.id, "error": str(exc)})
        await db.commit()
    return touched


async def loop(session_factory) -> None:
    while True:
        try:
            await process_running(session_factory)
        except Exception:
            logger.exception("fallo el ciclo de simulacros")
        await asyncio.sleep(POLL_SECONDS)
