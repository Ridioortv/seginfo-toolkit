"""Integracion con AntiEstafa AR (servicio de tecnoros.ar que revisa mensajes, audios, links y QR de las personas).

AntiEstafa cubre lo que le llega a las PERSONAS (el WhatsApp falso del "gerente", el audio del "banco") y avisa a TERO
cuando un empleado revisa algo que da ESTAFA o SOSPECHOSO. Aca se recibe ese aviso (JSON tipo ECS), se lo convierte a
un documento ECS-lite de TERO con SOLO los campos que se esperan (nada de lo que mande el cliente se indexa tal cual),
y de ahi sigue el camino normal: reglas Sigma -> alerta -> SOAR (notificar y abrir caso) -> cadena de custodia.

Privacidad: por defecto AntiEstafa no manda el texto del mensaje ni lo que dice el audio, solo veredicto, canal,
senales, dominios y una huella corta. Si la empresa pidio mandar el texto, se guarda recortado.

Que NO hace: no ejecuta nada contra el mensaje, no abre links, no bloquea dominios. Detecta lo que las personas
reportan; no reemplaza una proteccion automatica de correo o de red."""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, RuleSeverity, SigmaRule

MODULE = "antiestafa"
INGEST_PATH = "/integrations/antiestafa/events"
MAX_BODY_BYTES = 64 * 1024
OUTCOMES = ("estafa", "sospechoso")   # lo unico que puede mandar AntiEstafa; "campana" solo la genera TERO
CHANNELS = ("mensaje", "captura", "audio", "link", "qr", "bot")
CAMPAIGN_REPORTS = int(os.getenv("ANTIESTAFA_CAMPAIGN_REPORTS", "3"))
CAMPAIGN_HOURS = float(os.getenv("ANTIESTAFA_CAMPAIGN_HOURS", "24"))
_ORG_RE = re.compile(r"^[A-Za-z0-9_-]{1,36}$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_DOMAIN_RE = re.compile(r"^[a-z0-9._-]{1,253}$")

# Reglas Sigma de la integracion (las mismas de integraciones/tero/sigma/ de AntiEstafa, en el formato de TERO).
# Las tres de AntiEstafa mas una de TERO: la misma estafa reportada varias veces es una campana en curso.
# La regla "estafa" excluye los audios para que un audio no genere dos alertas y dos casos (lo toma la de voz clonada).
_TAGS_COMMON = ["antiestafa", "phishing"]
RULES: list[dict] = [
    {
        "name": "AntiEstafa: estafa o phishing detectado por un empleado",
        "description": ("Un empleado reviso en AntiEstafa AR un mensaje, link o QR y el resultado fue ESTAFA: intento de "
                        "phishing o fraude dirigido a la organizacion. Falso positivo posible: un mensaje legitimo que "
                        "el analisis marco por error."),
        "severity": "high",
        "tags": _TAGS_COMMON + ["attack.initial-access", "attack.t1566", "attack.t1566.002", "attack.reconnaissance",
                                "attack.t1598"],
        "detection": {"selection_1": {"event.module": MODULE, "event.outcome": "estafa"},
                      "selection_audio": {"antiestafa.canal": "audio"},
                      "condition": "selection_1 and not selection_audio"},
    },
    {
        "name": "AntiEstafa: mensaje sospechoso reportado por un empleado",
        "description": ("Un empleado reviso en AntiEstafa AR algo que dio SOSPECHOSO. Conviene revisarlo y, si se repite, "
                        "avisar al resto de la organizacion. Falso positivo posible: mensajes comerciales legitimos con "
                        "apuro o links acortados."),
        "severity": "medium",
        "tags": _TAGS_COMMON + ["attack.initial-access", "attack.t1566"],
        "detection": {"selection_1": {"event.module": MODULE, "event.outcome": "sospechoso"}, "condition": "selection_1"},
    },
    {
        "name": "AntiEstafa: estafa por audio o llamada (posible voz clonada)",
        "description": ("Un empleado reviso un audio o una llamada grabada y dio ESTAFA: alguien se hace pasar por un "
                        "directivo, un proveedor o el banco por voz (vishing). Hoy las voces se pueden imitar con IA. "
                        "Falso positivo posible: audios legitimos de un familiar o companero que pide un favor con apuro."),
        "severity": "critical",
        "tags": _TAGS_COMMON + ["attack.initial-access", "attack.t1566", "attack.t1566.004"],
        "detection": {"selection_1": {"event.module": MODULE, "event.outcome": "estafa", "antiestafa.canal": "audio"},
                      "condition": "selection_1"},
    },
    {
        "name": "AntiEstafa: la misma estafa llego varias veces (campana en curso)",
        "description": (f"El mismo dominio o el mismo mensaje fue reportado {CAMPAIGN_REPORTS} o mas veces en "
                        f"{CAMPAIGN_HOURS:g} horas: probablemente hay una campana dirigida a la organizacion. Conviene "
                        "avisar a todo el personal. TERO cuenta reportes; no puede saber si vinieron de personas distintas."),
        "severity": "high",
        "tags": _TAGS_COMMON + ["attack.initial-access", "attack.t1566", "campaign"],
        "detection": {"selection_1": {"event.module": MODULE, "event.outcome": "campana"}, "condition": "selection_1"},
    },
]
RULE_NAMES = [r["name"] for r in RULES]


# Ultimo aviso recibido por organizacion (en memoria: sirve para confirmar la conexion, se pierde al reiniciar).
LAST_SEEN: dict[str, dict] = {}


def record_seen(organization_id: str, test: bool) -> None:
    LAST_SEEN[organization_id] = {"at": _now().isoformat(), "test": test}


class AntiEstafaError(ValueError):
    """El evento recibido no tiene la forma esperada (se responde 422 con el motivo)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def _text(v, limit: int) -> str:
    return str(v).replace("\x00", "").strip()[:limit] if v is not None and not isinstance(v, (dict, list)) else ""


def _str_list(v, limit_items: int, limit_chars: int) -> list[str]:
    if not isinstance(v, list):
        return []
    out = []
    for item in v:
        t = _text(item, limit_chars)
        if t and t not in out:
            out.append(t)
        if len(out) >= limit_items:
            break
    return out


def org_from_event(raw: dict) -> str | None:
    org = _text(_as_dict(raw.get("organization")).get("id"), 64)
    if not org:
        return None
    if not _ORG_RE.match(org):
        raise AntiEstafaError("organization.id no es valido (hasta 36 letras, numeros, guion o guion bajo)")
    return org


def _timestamp(raw: dict) -> str:
    ts = _text(raw.get("@timestamp"), 40)
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        # un reloj muy adelantado no debe dejar un evento "en el futuro" fuera de las ventanas de 24 h
        return min(parsed, _now()).isoformat()
    except ValueError:
        return _now().isoformat()


def is_test_event(raw: dict) -> bool:
    """Los eventos de `npm run tero:prueba` van marcados [PRUEBA]: prueban la conexion, no abren alertas ni casos."""
    message = _text(raw.get("message"), 200)
    labels = _as_dict(raw.get("labels"))
    return message.upper().startswith("[PRUEBA]") or str(labels.get("prueba", "")).lower() in ("true", "1", "si")


def _threat(raw: dict) -> dict:
    threat = _as_dict(raw.get("threat"))
    techniques = []
    for t in threat.get("technique") or []:
        t = _as_dict(t)
        tid = _text(t.get("id"), 12).upper()
        if not _TECHNIQUE_RE.match(tid):
            continue
        item = {"id": tid, "name": _text(t.get("name"), 80)}
        subs = [{"id": _text(_as_dict(s).get("id"), 12).upper(), "name": _text(_as_dict(s).get("name"), 80)}
                for s in (t.get("subtechnique") or []) if _TECHNIQUE_RE.match(_text(_as_dict(s).get("id"), 12).upper())]
        if subs:
            item["subtechnique"] = subs[:5]
        techniques.append(item)
    return {"framework": "MITRE ATT&CK", "technique": techniques[:10]} if techniques else {}


def build_document(raw: dict, organization_id: str) -> dict:
    """Convierte el evento de AntiEstafa en un documento ECS-lite de TERO. Falla con AntiEstafaError si no es de AntiEstafa."""
    if not isinstance(raw, dict):
        raise AntiEstafaError("El cuerpo tiene que ser un objeto JSON")
    event = _as_dict(raw.get("event"))
    if _text(event.get("module"), 40).lower() != MODULE:
        raise AntiEstafaError("event.module tiene que ser 'antiestafa'")
    outcome = _text(event.get("outcome"), 20).lower()
    if outcome not in OUTCOMES:
        raise AntiEstafaError("event.outcome tiene que ser 'estafa' o 'sospechoso'")
    ae = _as_dict(raw.get("antiestafa"))
    canal = _text(ae.get("canal"), 20).lower()
    canal = canal if canal in CHANNELS else "otro"
    try:
        score = max(0, min(100, int(ae.get("score", event.get("severity", 0)))))
    except (TypeError, ValueError):
        score = 0
    dominios = [d.lower() for d in _str_list(ae.get("dominios"), 20, 300) if _DOMAIN_RE.match(d.lower())]
    antiestafa = {
        "veredicto": outcome, "score": score, "canal": canal,
        "banderas": _str_list(ae.get("banderas"), 20, 200), "dominios": dominios,
        "sin_ia": bool(ae.get("sin_ia", False)), "huella": _text(ae.get("huella"), 64),
    }
    for key in ("texto", "transcripcion"):  # solo llegan si la empresa pidio TERO_INCLUIR_TEXTO=true
        if ae.get(key):
            antiestafa[key] = _text(ae.get(key), 2000)
    severity = {"estafa": "high", "sospechoso": "medium", "campana": "high"}[outcome]
    if outcome == "estafa" and canal == "audio":
        severity = "critical"
    return {
        "@timestamp": _timestamp(raw),
        "organization_id": organization_id,
        "host": {"name": "antiestafa"},
        "source": {"ip": ""}, "destination": {"ip": ""}, "user": {"name": ""},
        "event": {"action": "antiestafa_analisis", "category": "phishing", "outcome": outcome, "module": MODULE,
                  "dataset": "antiestafa.analisis", "provider": "AntiEstafa AR", "kind": "alert"},
        "message": _text(raw.get("message"), 500) or f"AntiEstafa: {outcome} en {canal}",
        "threat": _threat(raw),
        "tags": [MODULE] + [t for t in _str_list(raw.get("tags"), 12, 60) if t != MODULE],
        "antiestafa": antiestafa,
        "sentinelops": {"source_type": MODULE, "asset_id": None, "severity": severity, "raw": ""},
    }


def campaign_document(organization_id: str, key: str, count: int) -> dict:
    kind, _, value = key.partition(":")
    what = f"el dominio {value}" if kind == "dominio" else "el mismo mensaje"
    return {
        "@timestamp": _now().isoformat(), "organization_id": organization_id, "host": {"name": "antiestafa"},
        "source": {"ip": ""}, "destination": {"ip": ""}, "user": {"name": ""},
        "event": {"action": "antiestafa_campana", "category": "phishing", "outcome": "campana", "module": MODULE,
                  "dataset": "antiestafa.campana", "provider": "TERO Security", "kind": "alert"},
        "message": f"AntiEstafa: {what} fue reportado {count} veces en {CAMPAIGN_HOURS:g} horas",
        "threat": {"framework": "MITRE ATT&CK", "technique": [{"id": "T1566", "name": "Phishing"}]},
        "tags": [MODULE, "campaign"],
        "antiestafa": {"veredicto": "campana", "score": 0, "canal": "", "banderas": [],
                       "dominios": [value] if kind == "dominio" else [], "sin_ia": False,
                       "huella": value if kind == "huella" else "", "campana_clave": key, "reportes": count},
        "sentinelops": {"source_type": MODULE, "asset_id": None, "severity": "high", "raw": ""},
    }


def keys_of(doc: dict) -> set[str]:
    ae = _as_dict(doc.get("antiestafa"))
    keys = {f"dominio:{d}" for d in ae.get("dominios") or []}
    if ae.get("huella"):
        keys.add(f"huella:{ae['huella']}")
    return keys


def _is_report(doc: dict) -> bool:
    d = _as_dict(doc)
    return _as_dict(d.get("event")).get("module") == MODULE and _as_dict(d.get("event")).get("outcome") in ("estafa", "sospechoso")


async def recent_alert_docs(db: AsyncSession, organization_id: str, since: datetime) -> list[tuple[Alert, dict]]:
    """Alertas de AntiEstafa de la organizacion desde `since` (el filtro por modulo se hace en Python: el campo es JSON)."""
    rows = (await db.execute(select(Alert).where(Alert.organization_id == organization_id, Alert.created_at >= since)
                             .order_by(Alert.created_at.desc()).limit(3000))).scalars().all()
    return [(a, a.matched_event) for a in rows if _as_dict(a.matched_event).get("event", {}).get("module") == MODULE]


def _distinct_reports(docs: list[dict]) -> list[dict]:
    """Un mismo reporte puede disparar mas de una regla: se cuenta una vez (misma hora, huella y canal)."""
    seen, out = set(), []
    for d in docs:
        ae = _as_dict(d.get("antiestafa"))
        ident = (d.get("@timestamp"), ae.get("huella"), ae.get("canal"), tuple(ae.get("dominios") or []))
        if ident not in seen:
            seen.add(ident)
            out.append(d)
    return out


async def new_campaign_keys(db: AsyncSession, organization_id: str, doc: dict) -> list[tuple[str, int]]:
    """Claves (dominio o huella) de `doc` que acaban de llegar justo al umbral de reportes en la ventana y todavia
    no tienen una alerta de campana. Se llama despues de guardar las alertas de `doc`."""
    if not _is_report(doc):
        return []
    keys = keys_of(doc)
    if not keys:
        return []
    since = _now() - timedelta(hours=CAMPAIGN_HOURS)
    pairs = await recent_alert_docs(db, organization_id, since)
    reports = _distinct_reports([d for _, d in pairs if _is_report(d)])
    already = {_as_dict(d.get("antiestafa")).get("campana_clave") for _, d in pairs
               if _as_dict(d.get("event")).get("outcome") == "campana"}
    result = []
    for key in sorted(keys):
        count = sum(1 for d in reports if key in keys_of(d))
        if count >= CAMPAIGN_REPORTS and key not in already:
            result.append((key, count))
    return result


async def seed_rules(db: AsyncSession, organization_id: str) -> list[SigmaRule]:
    existing = {row[0] for row in (await db.execute(select(SigmaRule.name).where(SigmaRule.organization_id == organization_id))).all()}
    created = []
    for spec in RULES:
        if spec["name"] in existing:
            continue
        rule = SigmaRule(organization_id=organization_id, name=spec["name"], description=spec["description"],
                         severity=RuleSeverity(spec["severity"]), tags=list(spec["tags"]), detection=spec["detection"],
                         is_enabled=True)
        db.add(rule)
        created.append(rule)
    if created:
        await db.flush()
        for r in created:
            await db.refresh(r)
    return created


async def status(db: AsyncSession, organization_id: str, days: int = 7) -> dict:
    rules = (await db.execute(select(SigmaRule).where(SigmaRule.organization_id == organization_id,
                                                      SigmaRule.name.in_(RULE_NAMES)))).scalars().all()
    active = {r.name for r in rules if r.is_enabled}
    pairs = await recent_alert_docs(db, organization_id, _now() - timedelta(days=days))
    docs = [d for _, d in pairs]
    reports = _distinct_reports([d for d in docs if _is_report(d)])
    by_outcome: dict[str, int] = {}
    by_channel: dict[str, int] = {}
    domains: dict[str, int] = {}
    for d in reports:
        ae = _as_dict(d.get("antiestafa"))
        by_outcome[ae.get("veredicto", "")] = by_outcome.get(ae.get("veredicto", ""), 0) + 1
        by_channel[ae.get("canal", "")] = by_channel.get(ae.get("canal", ""), 0) + 1
        for dom in ae.get("dominios") or []:
            domains[dom] = domains.get(dom, 0) + 1
    campaigns = [{"key": _as_dict(d.get("antiestafa")).get("campana_clave", ""), "reports": _as_dict(d.get("antiestafa")).get("reportes", 0),
                  "at": d.get("@timestamp")} for d in docs if _as_dict(d.get("event")).get("outcome") == "campana"]
    last = max((d.get("@timestamp") for d in reports), default=None)
    return {
        "organization_id": organization_id, "ingest_path": INGEST_PATH, "window_days": days,
        "rules": {"expected": len(RULES), "active": len(active), "missing": [n for n in RULE_NAMES if n not in active]},
        "reports": len(reports), "by_outcome": by_outcome, "by_channel": by_channel,
        "top_domains": [{"domain": k, "count": v} for k, v in sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[:10]],
        "campaigns": campaigns[:10], "last_report_at": last, "last_received": LAST_SEEN.get(organization_id),
        "campaign_threshold": {"reports": CAMPAIGN_REPORTS, "hours": CAMPAIGN_HOURS},
    }
