"""Evidencia viva para el cumplimiento: consulta datos REALES de los otros servicios (con un JWT de servicio de la
organizacion) y los convierte en el resultado de cada control automatico.

Reglas:
  * Nada se inventa ni se redondea para arriba. Si una fuente no responde, el control queda `sin_datos` (no
    `cumple`) y se dice cual fue la fuente.
  * Cada resultado trae las observaciones que lo respaldan (que se miro, que valor dio, de que servicio).
  * Los textos son plantillas con {0}, {1}... y sus valores aparte (`m(texto, *args)`), asi la pantalla los traduce.

Estados de un control automatico: cumple | parcial | no_cumple | sin_datos."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.service_auth import service_auth_headers
from app import custody_service as custody
from app import egress_service as egress
from app.models import Case, CaseStatus

TIMEOUT_SECONDS = 8.0
STALE_CASE_DAYS = 14
LOGS_FRESH_HOURS = 48
ADMIN_ROLES = ("admin",)

URLS = {
    "auth": os.getenv("AUTH_SERVICE_URL", "http://auth-service:8000"),
    "asset": os.getenv("ASSET_SERVICE_URL", "http://asset-service:8000"),
    "scan": os.getenv("SCAN_SERVICE_URL", "http://scan-service:8000"),
    "vuln": os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000"),
    "siem": os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000"),
    "soar": os.getenv("SOAR_SERVICE_URL", "http://soar-service:8000"),
    "purple": os.getenv("PURPLE_SERVICE_URL", "http://purple-service:8000"),
}
SERVICE_NAME = {"auth": "auth-service", "asset": "asset-service", "scan": "scan-service", "vuln": "vuln-service",
                "siem": "siem-service", "soar": "soar-service", "purple": "purple-service", "case": "case-service"}


def m(text: str, *args) -> dict:
    return {"text": text, "args": [str(a) for a in args]}


def ev(label: str, value, source: str) -> dict:
    return {"label": label, "value": str(value), "source": source}


class NoData(Exception):
    def __init__(self, source: str, error: str = ""):
        super().__init__(source)
        self.source, self.error = source, error


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


# ----------------------------- recoleccion -----------------------------

async def _get(client: httpx.AsyncClient, org_id: str | None, key: str, path: str, params: dict | None = None) -> dict:
    try:
        resp = await client.get(f"{URLS[key]}{path}", params=params, headers=service_auth_headers("case-service", org_id))
    except httpx.HTTPError as exc:
        return {"ok": False, "error": exc.__class__.__name__}
    if resp.status_code >= 300:
        return {"ok": False, "error": f"HTTP {resp.status_code}"}
    try:
        return {"ok": True, "data": resp.json()}
    except ValueError:
        return {"ok": False, "error": "respuesta invalida"}


async def _local(coro) -> dict:
    try:
        return {"ok": True, "data": await coro}
    except Exception as exc:  # una fuente local rota no tumba la evaluacion entera
        return {"ok": False, "error": exc.__class__.__name__}


async def _cases(db: AsyncSession, org_id: str | None) -> dict:
    rows = (await db.execute(select(Case.status, Case.updated_at, Case.created_at).where(Case.organization_id == org_id))).all()
    now = _now()
    stale = 0
    for status, updated, created in rows:
        value = getattr(status, "value", status)
        if value in (CaseStatus.open.value, CaseStatus.in_progress.value):
            last = _aware(updated) or _aware(created) or now
            if now - last > timedelta(days=STALE_CASE_DAYS):
                stale += 1
    total = len(rows)
    open_now = sum(1 for s, *_ in rows if getattr(s, "value", s) in ("open", "in_progress"))
    return {"total": total, "open": open_now, "stale_open": stale}


async def gather(db: AsyncSession, org_id: str | None, client: httpx.AsyncClient | None = None) -> dict:
    """Junta todas las fuentes en paralelo. Devuelve {fuente: {ok, data|error}}."""
    own = client is None
    client = client or httpx.AsyncClient(timeout=TIMEOUT_SECONDS)
    org = org_id or ""
    try:
        keys = ["users", "sso", "assets", "scans", "posture", "closure", "siem_latest", "siem_rules", "playbooks", "drills"]
        remote = await asyncio.gather(
            _get(client, org_id, "auth", f"/auth/organizations/{org}/users"),
            _get(client, org_id, "auth", f"/auth/organizations/{org}/sso"),
            _get(client, org_id, "asset", "/assets"),
            _get(client, org_id, "scan", "/scans/summary"),
            _get(client, org_id, "vuln", "/vulnerabilities/posture"),
            _get(client, org_id, "vuln", "/vulnerabilities/closure/stats"),
            _get(client, org_id, "siem", "/logs/search", {"size": 1}),
            _get(client, org_id, "siem", "/rules", {"enabled_only": "true"}),
            _get(client, org_id, "soar", "/playbooks"),
            _get(client, org_id, "purple", "/drills/stats"),
        )
        facts = dict(zip(keys, remote))
    finally:
        if own:
            await client.aclose()
    facts["custody"] = await _local(custody.verify(db, org_id))
    facts["cases"] = await _local(_cases(db, org_id))
    facts["sovereignty"] = await _local(egress.status(db))
    return facts


def need(facts: dict, key: str, source: str):
    f = facts.get(key) or {"ok": False, "error": "sin respuesta"}
    if not f["ok"]:
        raise NoData(source, f.get("error", ""))
    return f["data"]


# ----------------------------- comprobaciones -----------------------------

def _res(status: str, summary: dict, evidence: list[dict]) -> dict:
    return {"status": status, "summary": summary, "evidence": evidence}


def _active_local_users(users: list[dict]) -> tuple[list[dict], int]:
    active = [u for u in users if u.get("is_active")]
    local = [u for u in active if (u.get("auth_provider") or "local") == "local"]
    return local, len(active) - len(local)


def check_mfa_admins(f: dict) -> dict:
    users = need(f, "users", "auth-service")
    local, delegated = _active_local_users(users)
    admins = [u for u in local if u.get("role_name") in ADMIN_ROLES]
    with_mfa = [u for u in admins if u.get("mfa_enabled")]
    e = [ev("Administradores con cuenta propia", len(admins), "auth-service"),
         ev("De ellos, con MFA activado", len(with_mfa), "auth-service")]
    if delegated:
        e.append(ev("Cuentas que entran por un proveedor de identidad (SSO)", delegated, "auth-service"))
    if not admins:
        if delegated:
            return _res("sin_datos", m("Los administradores entran por SSO: el MFA lo controla tu proveedor de identidad y TERO no puede comprobarlo. Declaralo a mano."), e)
        return _res("sin_datos", m("No hay cuentas administradoras activas para evaluar."), e)
    if len(with_mfa) == len(admins):
        return _res("cumple", m("Los {0} administradores tienen MFA activado.", len(admins)), e)
    if not with_mfa:
        return _res("no_cumple", m("Ninguno de los {0} administradores tiene MFA activado.", len(admins)), e)
    return _res("parcial", m("{0} de {1} administradores tienen MFA activado.", len(with_mfa), len(admins)), e)


def check_mfa_all(f: dict) -> dict:
    users = need(f, "users", "auth-service")
    local, delegated = _active_local_users(users)
    with_mfa = [u for u in local if u.get("mfa_enabled")]
    e = [ev("Usuarios activos con cuenta propia", len(local), "auth-service"),
         ev("De ellos, con MFA activado", len(with_mfa), "auth-service")]
    if delegated:
        e.append(ev("Cuentas que entran por un proveedor de identidad (SSO)", delegated, "auth-service"))
    if not local:
        return _res("sin_datos", m("No hay usuarios con cuenta propia para evaluar."), e)
    if len(with_mfa) == len(local):
        return _res("cumple", m("Los {0} usuarios activos tienen MFA activado.", len(local)), e)
    pct = round(100 * len(with_mfa) / len(local))
    if pct >= 50:
        return _res("parcial", m("{0} de {1} usuarios activos tienen MFA activado ({2}%).", len(with_mfa), len(local), pct), e)
    return _res("no_cumple", m("Solo {0} de {1} usuarios activos tienen MFA activado ({2}%).", len(with_mfa), len(local), pct), e)


def check_admin_share(f: dict) -> dict:
    users = need(f, "users", "auth-service")
    active = [u for u in users if u.get("is_active")]
    admins = [u for u in active if u.get("role_name") in ADMIN_ROLES]
    e = [ev("Cuentas activas", len(active), "auth-service"), ev("Cuentas administradoras", len(admins), "auth-service")]
    if not active:
        return _res("sin_datos", m("No hay cuentas activas para evaluar."), e)
    if len(admins) <= 3 or len(admins) * 3 <= len(active):
        return _res("cumple", m("Hay {0} cuentas administradoras sobre {1} activas.", len(admins), len(active)), e)
    return _res("no_cumple", m("Hay {0} cuentas administradoras sobre {1} activas: son demasiadas para el minimo privilegio.", len(admins), len(active)), e)


def check_assets_inventory(f: dict) -> dict:
    assets = need(f, "assets", "asset-service")
    with_owner = [a for a in assets if str(a.get("owner") or "").strip()]
    e = [ev("Equipos y servidores activos cargados", len(assets), "asset-service"),
         ev("Con responsable asignado", len(with_owner), "asset-service")]
    if not assets:
        return _res("no_cumple", m("Todavia no hay equipos ni servidores cargados en el inventario."), e)
    pct = round(100 * len(with_owner) / len(assets))
    if pct >= 90:
        return _res("cumple", m("{0} activos inventariados, {1}% con responsable.", len(assets), pct), e)
    return _res("parcial", m("{0} activos inventariados, pero solo {1}% tiene responsable asignado.", len(assets), pct), e)


def check_scans_recent(f: dict) -> dict:
    s = need(f, "scans", "scan-service")
    recent, sched = int(s.get("completed_in_window") or 0), int(s.get("schedules_enabled") or 0)
    e = [ev("Escaneos terminados en los ultimos 30 dias", recent, "scan-service"),
         ev("Escaneos programados activos", sched, "scan-service")]
    if s.get("last_completed_at"):
        e.append(ev("Ultimo escaneo terminado", s["last_completed_at"], "scan-service"))
    if recent and sched:
        return _res("cumple", m("{0} escaneos terminados en los ultimos 30 dias y {1} programados activos.", recent, sched), e)
    if recent:
        return _res("parcial", m("Hubo {0} escaneos en los ultimos 30 dias pero ninguno esta programado: depende de que alguien se acuerde.", recent), e)
    if sched:
        return _res("parcial", m("Hay {0} escaneos programados pero ninguno termino en los ultimos 30 dias.", sched), e)
    return _res("no_cumple", m("No hubo escaneos terminados en los ultimos 30 dias ni hay escaneos programados."), e)


def check_vulns_open_critical(f: dict) -> dict:
    p = need(f, "posture", "vuln-service")
    sev = p.get("open_by_severity") or {}
    crit, high, kev = int(sev.get("critical", 0)), int(sev.get("high", 0)), int(p.get("open_kev", 0))
    oldest = (p.get("oldest_open_days") or {}).get("critical", 0)
    e = [ev("Criticas abiertas", crit, "vuln-service"), ev("Altas abiertas", high, "vuln-service"),
         ev("Explotadas activamente (KEV) abiertas", kev, "vuln-service")]
    if crit:
        e.append(ev("Dias de la critica abierta mas vieja", oldest, "vuln-service"))
    if not crit and not kev:
        return _res("cumple", m("No hay vulnerabilidades criticas ni explotadas activamente abiertas ({0} altas abiertas).", high), e)
    if crit and kev:
        return _res("no_cumple", m("Hay {0} criticas y {1} explotadas activamente sin corregir.", crit, kev), e)
    if kev:
        return _res("no_cumple", m("Hay {0} vulnerabilidades explotadas activamente sin corregir.", kev), e)
    return _res("parcial" if oldest <= 30 else "no_cumple",
                m("Hay {0} criticas abiertas; la mas vieja lleva {1} dias.", crit, oldest), e)


def check_closure_verified(f: dict) -> dict:
    c = need(f, "closure", "vuln-service")
    counts = c.get("counts") or {}
    verified, failed = int(counts.get("verified", 0)), int(counts.get("failed", 0))
    unverified, total = int(c.get("remediated_unverified", 0)), int(c.get("remediated_total", 0))
    e = [ev("Cierres verificados con un nuevo escaneo", verified, "vuln-service"),
         ev("Cierres que fallaron (se reabrieron)", failed, "vuln-service"),
         ev("Remediadas sin verificar", unverified, "vuln-service")]
    if total == 0 and verified == 0 and failed == 0:
        return _res("sin_datos", m("Todavia no hay vulnerabilidades remediadas para verificar."), e)
    if verified and not unverified:
        return _res("cumple", m("{0} cierres verificados con un nuevo escaneo y ninguno pendiente de verificar.", verified), e)
    if verified:
        return _res("parcial", m("{0} cierres verificados, pero {1} remediadas siguen sin verificar.", verified, unverified), e)
    return _res("no_cumple", m("Hay {0} vulnerabilidades marcadas como remediadas y ninguna esta verificada.", max(total, unverified)), e)


def check_siem_recent(f: dict) -> dict:
    hits = need(f, "siem_latest", "siem-service")
    last = None
    if isinstance(hits, list) and hits:
        last = _parse(hits[0].get("@timestamp") or hits[0].get("timestamp"))
    if last is None:
        return _res("no_cumple", m("No se recibieron registros de actividad."),
                    [ev("Registros recibidos", 0, "siem-service")])
    age = _now() - last
    e = [ev("Ultimo registro recibido", last.isoformat(), "siem-service")]
    if age <= timedelta(hours=LOGS_FRESH_HOURS):
        return _res("cumple", m("El ultimo registro llego hace menos de {0} horas.", LOGS_FRESH_HOURS), e)
    return _res("parcial", m("El ultimo registro llego hace {0} dias: la recepcion se detuvo.", age.days), e)


def check_siem_rules(f: dict) -> dict:
    rules = need(f, "siem_rules", "siem-service")
    # las reglas propias de los simulacros (etiqueta tero-drill) no son deteccion real: no cuentan
    real = [r for r in rules if "tero-drill" not in [str(t).lower() for t in (r.get("tags") or [])]] if isinstance(rules, list) else []
    n = len(real)
    e = [ev("Reglas de deteccion activas", n, "siem-service")]
    if n:
        return _res("cumple", m("Hay {0} reglas de deteccion activas.", n), e)
    return _res("no_cumple", m("No hay reglas de deteccion activas."), e)


def check_custody_chain(f: dict) -> dict:
    v = need(f, "custody", "case-service")
    n = int(v.get("entries") or 0)
    e = [ev("Eventos en la cadena", n, "case-service"), ev("Cadena integra", "Si" if v.get("ok") else "No", "case-service")]
    if not n:
        return _res("sin_datos", m("La cadena de custodia todavia no tiene eventos."), e)
    if v.get("ok"):
        return _res("cumple", m("La cadena tiene {0} eventos firmados y su integridad se verifica.", n), e)
    return _res("no_cumple", m("La verificacion de la cadena de custodia fallo: {0}", str(v.get("reason") or "")[:200]), e)


def check_soar_playbooks(f: dict) -> dict:
    pbs = need(f, "playbooks", "soar-service")
    enabled = [p for p in pbs if p.get("is_enabled")] if isinstance(pbs, list) else []
    e = [ev("Playbooks de respuesta activos", len(enabled), "soar-service")]
    if enabled:
        return _res("cumple", m("Hay {0} playbooks de respuesta automatizada activos.", len(enabled)), e)
    return _res("no_cumple", m("No hay playbooks de respuesta activos."), e)


def check_drills_recent(f: dict) -> dict:
    d = need(f, "drills", "purple-service")
    total, days, last = int(d.get("completed_total") or 0), d.get("days_since_last"), d.get("last_score")
    e = [ev("Simulacros completados", total, "purple-service")]
    if last is not None:
        e.append(ev("Puntaje del ultimo simulacro", last, "purple-service"))
    if days is not None:
        e.append(ev("Dias desde el ultimo simulacro", days, "purple-service"))
    if d.get("median_ack_seconds") is not None:
        e.append(ev("Tiempo mediano hasta reconocer la alerta (segundos)", d["median_ack_seconds"], "purple-service"))
    if total == 0:
        return _res("no_cumple", m("Todavia no se hizo ningun simulacro de respuesta."), e)
    if days is not None and days <= 180 and last is not None and last >= 70:
        return _res("cumple", m("El ultimo simulacro fue hace {0} dias y saco {1} puntos.", round(days), last), e)
    if days is not None and days > 180:
        return _res("parcial", m("El ultimo simulacro fue hace {0} dias: conviene repetirlo al menos cada 6 meses.", round(days)), e)
    return _res("parcial", m("El ultimo simulacro saco {0} puntos: el equipo tiene que mejorar los tiempos de respuesta.", last), e)


def check_cases_handling(f: dict) -> dict:
    c = need(f, "cases", "case-service")
    e = [ev("Casos registrados", c["total"], "case-service"), ev("Casos abiertos", c["open"], "case-service"),
         ev("Abiertos sin movimiento hace mas de 14 dias", c["stale_open"], "case-service")]
    if c["total"] == 0:
        return _res("sin_datos", m("Todavia no se registraron casos: no hay incidentes que evaluar."), e)
    if c["stale_open"] == 0:
        return _res("cumple", m("{0} casos registrados y ninguno abierto esta abandonado.", c["total"]), e)
    return _res("parcial", m("Hay {0} casos abiertos sin movimiento hace mas de {1} dias.", c["stale_open"], STALE_CASE_DAYS), e)


VERDICT_LABEL = {
    "no_data": "Sin datos", "unexpected": "Conexiones inesperadas", "controlled": "Salidas controladas",
    "isolated_unverified": "Aislado sin comprobar", "isolated_verified": "Aislado y comprobado",
}


def check_sovereignty(f: dict) -> dict:
    s = need(f, "sovereignty", "case-service")
    verdict = s.get("verdict", "no_data")
    summ = s.get("summary") or {}
    e = [ev("Veredicto de soberania", VERDICT_LABEL.get(verdict, "Sin datos"), "case-service"),
         ev("Destinos externos vistos", summ.get("external_destinations", 0), "case-service"),
         ev("Destinos sin catalogar", summ.get("unknown_destinations", 0), "case-service")]
    if verdict == "isolated_verified":
        return _res("cumple", m("Modo aislado comprobado con una prueba de red: no hay salida a internet."), e)
    if verdict in ("controlled", "isolated_unverified"):
        return _res("cumple" if verdict == "controlled" else "parcial",
                    m("Todas las salidas externas estan catalogadas y a la vista.") if verdict == "controlled"
                    else m("El modo aislado esta activo pero falta la prueba de red que lo confirme."), e)
    if verdict == "unexpected":
        return _res("no_cumple", m("Hay conexiones a destinos externos que no estan catalogados: revisalas en Soberania."), e)
    return _res("sin_datos", m("Todavia no hay informes de salidas a internet."), e)


CHECKS = {
    "mfa_admins": check_mfa_admins, "mfa_all": check_mfa_all, "admin_share": check_admin_share,
    "assets_inventory": check_assets_inventory, "scans_recent": check_scans_recent,
    "vulns_open_critical": check_vulns_open_critical, "closure_verified": check_closure_verified,
    "siem_recent": check_siem_recent, "siem_rules": check_siem_rules, "custody_chain": check_custody_chain,
    "soar_playbooks": check_soar_playbooks, "drills_recent": check_drills_recent, "cases_handling": check_cases_handling, "sovereignty": check_sovereignty,
}


def run_check(name: str, facts: dict) -> dict:
    try:
        return CHECKS[name](facts)
    except NoData as exc:
        return _res("sin_datos", m("No se pudo consultar {0}.", f"{exc.source} ({exc.error})" if exc.error else exc.source), [])
    except Exception as exc:  # una comprobacion rota no debe dar un "cumple" ni tumbar el resto
        return _res("sin_datos", m("La comprobacion fallo ({0}).", exc.__class__.__name__), [])
