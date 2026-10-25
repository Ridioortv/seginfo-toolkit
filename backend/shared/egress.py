"""Auditor de salidas a internet y MODO AISLADO (prueba de soberania).

Que resuelve: poder decir, con evidencia, "TERO no manda datos a ningun lado que no hayas visto".

Como:
  * Cada servicio instala este modulo (`egress.install("nombre", app)`). A partir de ahi toda llamada
    HTTP saliente (httpx) pasa por un control que anota el DESTINO (solo el nombre de host; nunca la ruta,
    los parametros ni el contenido) y lo cuenta. Lo interno (nombres de servicio de Docker, localhost,
    IP privadas) no se informa: solo importan las salidas.
  * Las conexiones que no son httpx (SMTP, AWS, git clone, validacion de Google) llaman a `guard(...)`
    antes de salir.
  * Cada minuto el servicio le informa lo observado a case-service (mismo mecanismo de token servicio
    a servicio que la cadena de custodia). Si case-service no responde, se reintenta con lo acumulado.
  * MODO AISLADO (`TERO_ISOLATED_MODE=1`): toda salida a un destino externo que no este en la lista
    permitida (`TERO_EGRESS_ALLOW`, separada por comas) se BLOQUEA antes de salir y queda anotada como
    bloqueada. Esto es un control de la aplicacion: la prueba de verdad es de red (ver docs).

Limites honestos: solo se ve lo que pasa por httpx o por `guard()`. Un binario externo (trivy, nuclei,
git) que el servicio lance como proceso no pasa por aca: por eso el modo aislado se complementa con una red
sin salida (docker-compose.aislado.yml) y con la prueba de conectividad que hace case-service."""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx

from backend.shared.logging import configure_logging
from backend.shared.service_auth import service_auth_headers

logger = configure_logging("egress")

REPORT_INTERVAL_SECONDS = int(os.getenv("TERO_EGRESS_REPORT_SECONDS", "60"))
CASE_SERVICE_URL = os.getenv("CASE_SERVICE_URL", "http://case-service:8000")
_INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".corp", ".home.arpa", ".svc", ".cluster.local")
MAX_DESTINATIONS = 500
MAX_PURPOSES = 5

_lock = threading.Lock()
_stats: dict[tuple[str, str], dict] = {}
_service_name = ""
_installed = False
_boot = datetime.now(timezone.utc).isoformat()


class EgressBlocked(httpx.ConnectError):
    """Salida bloqueada por el modo aislado. Es un ConnectError: el codigo que ya maneja
    httpx.HTTPError lo trata como "no se pudo conectar", sin cambios."""

    def __init__(self, host: str):
        super().__init__(f"salida bloqueada por el modo aislado: {host}")
        self.host = host


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "si", "on")


def isolated() -> bool:
    return _truthy(os.getenv("TERO_ISOLATED_MODE", ""))


def _clean_host(host: str) -> str:
    return (host or "").strip().strip("[]").lower().rstrip(".")


def allowlist() -> set[str]:
    return {_clean_host(h) for h in os.getenv("TERO_EGRESS_ALLOW", "").split(",") if _clean_host(h)}


def _extra_internal_suffixes() -> tuple[str, ...]:
    return tuple("." + s.strip().lower().lstrip(".") for s in os.getenv("TERO_INTERNAL_DOMAINS", "").split(",") if s.strip())


def is_internal(host: str) -> bool:
    """True para lo que NO sale de la red propia: nombres de servicio de Docker (sin punto), localhost,
    IP privadas/loopback/link-local y dominios internos conocidos (.local, .lan, .corp, ...)."""
    h = _clean_host(host)
    if not h or h == "localhost":
        return True
    try:
        return not ipaddress.ip_address(h).is_global
    except ValueError:
        pass
    if "." not in h:
        return True
    return h.endswith(_INTERNAL_SUFFIXES + _extra_internal_suffixes())


def _allowed(host: str) -> bool:
    h = _clean_host(host)
    return any(h == a or h.endswith("." + a) for a in allowlist())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record(host: str, kind: str = "http", purpose: str = "", blocked: bool = False) -> None:
    h = _clean_host(host)
    if not h or is_internal(h):
        return
    key = (h, kind)
    with _lock:
        if key not in _stats and len(_stats) >= MAX_DESTINATIONS:
            return
        row = _stats.setdefault(key, {"count": 0, "blocked": 0, "first_seen": _now(), "last_seen": "", "purposes": []})
        row["count"] += 1
        if blocked:
            row["blocked"] += 1
        row["last_seen"] = _now()
        if purpose and purpose not in row["purposes"] and len(row["purposes"]) < MAX_PURPOSES:
            row["purposes"].append(purpose[:120])


def guard(host: str, kind: str = "http", purpose: str = "") -> None:
    """Se llama antes de una salida que no pasa por httpx. Anota el destino y, en modo aislado, lo frena."""
    h = _clean_host(host)
    if not h or is_internal(h):
        return
    if isolated() and not _allowed(h):
        record(h, kind, purpose, blocked=True)
        raise EgressBlocked(h)
    record(h, kind, purpose)


def _check_request(request: httpx.Request) -> None:
    guard(request.url.host, "http")


def pending() -> list[dict]:
    """Lo acumulado y todavia no informado (para pruebas)."""
    with _lock:
        return [{"host": h, "kind": k, **v} for (h, k), v in _stats.items()]


def snapshot_and_reset() -> list[dict]:
    with _lock:
        out = [{"host": h, "kind": k, **v} for (h, k), v in _stats.items()]
        _stats.clear()
    return out


def _restore(rows: list[dict]) -> None:
    """Devuelve lo que no se pudo informar para reintentarlo (se suma a lo nuevo)."""
    with _lock:
        for r in rows:
            key = (r["host"], r["kind"])
            cur = _stats.get(key)
            if cur is None:
                _stats[key] = {k: r[k] for k in ("count", "blocked", "first_seen", "last_seen", "purposes")}
            else:
                cur["count"] += r["count"]
                cur["blocked"] += r["blocked"]
                cur["first_seen"] = min(cur["first_seen"], r["first_seen"])
                cur["last_seen"] = max(cur["last_seen"], r["last_seen"])
                for p in r["purposes"]:
                    if p not in cur["purposes"] and len(cur["purposes"]) < MAX_PURPOSES:
                        cur["purposes"].append(p)


def build_report() -> dict:
    return {
        "service": _service_name, "instance": socket.gethostname(), "boot": _boot,
        "isolated": isolated(), "allowlist": sorted(allowlist()),
        "interval_seconds": REPORT_INTERVAL_SECONDS, "destinations": snapshot_and_reset(),
    }


async def flush() -> bool:
    """Informa a case-service lo observado. Devuelve False si no se pudo (queda para el proximo intento)."""
    if _truthy(os.getenv("TERO_EGRESS_DISABLED", "")) or not _service_name:
        return True
    report = build_report()
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{CASE_SERVICE_URL}/internal/egress/report", json=report,
                                     headers=service_auth_headers(_service_name))
        if resp.status_code >= 300:
            raise httpx.HTTPError(f"HTTP {resp.status_code}")
        return True
    except httpx.HTTPError as exc:
        _restore(report["destinations"])
        logger.debug("no se pudo informar salidas a case-service", extra={"error": str(exc)})
        return False


async def _loop() -> None:
    await asyncio.sleep(min(10, REPORT_INTERVAL_SECONDS))  # primer aviso rapido: se ve que el servicio esta vivo
    while True:
        try:
            await flush()
        except Exception as exc:  # nunca debe tumbar el servicio
            logger.warning("fallo el informe de salidas", extra={"error": str(exc)})
        await asyncio.sleep(REPORT_INTERVAL_SECONDS)


def _patch_httpx() -> None:
    global _installed
    if _installed:
        return
    orig_async = httpx.AsyncClient.send
    orig_sync = httpx.Client.send

    async def async_send(self, request, *args, **kwargs):
        _check_request(request)
        return await orig_async(self, request, *args, **kwargs)

    def sync_send(self, request, *args, **kwargs):
        _check_request(request)
        return orig_sync(self, request, *args, **kwargs)

    httpx.AsyncClient.send = async_send  # type: ignore[method-assign]
    httpx.Client.send = sync_send  # type: ignore[method-assign]
    _installed = True


def install(service: str, app=None) -> None:
    """Activa el auditor en este servicio. Con `app`, ademas arranca el informe periodico junto con el
    servicio (se engancha al lifespan existente, sin tocarlo)."""
    global _service_name
    _service_name = service
    _patch_httpx()
    if app is None or getattr(app.router, "_egress_wrapped", False):
        return
    original = app.router.lifespan_context

    @asynccontextmanager
    async def wrapped(a):
        task = asyncio.create_task(_loop())
        try:
            async with original(a) as state:
                yield state
        finally:
            task.cancel()

    app.router.lifespan_context = wrapped
    app.router._egress_wrapped = True


def reset_for_tests() -> None:
    with _lock:
        _stats.clear()
