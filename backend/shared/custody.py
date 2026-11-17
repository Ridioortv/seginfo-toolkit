"""Cliente para anotar eventos en la CADENA DE CUSTODIA de TERO (la guarda case-service).

Cada servicio llama a `record_event(...)` cuando pasa algo que pueda servir como evidencia (una alerta, una
accion de respuesta, un escaneo, el cierre de una vulnerabilidad...). Reglas de oro:

  * NUNCA rompe ni demora de mas el flujo que lo llama: si case-service no responde, el evento queda en
    una cola en memoria (hasta 500) y se reintenta en la siguiente llamada. Limite honesto: si el
    servicio que emite se reinicia con eventos en cola, esos eventos se pierden (queda un aviso en el log).
  * Solo se mandan datos necesarios para la evidencia, nunca el evento crudo completo: para eso se manda
    su huella SHA-256 (ver `digest`).
  * La organizacion sale del JWT de servicio que se emite aca con el organization_id del recurso.

TERO_CUSTODY_DISABLED=1 lo apaga (lo usan los tests de cada servicio)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections import deque

import httpx

from backend.shared.logging import configure_logging
from backend.shared.service_auth import service_auth_headers

logger = configure_logging("custody-client")

CASE_SERVICE_URL = os.getenv("CASE_SERVICE_URL", "http://case-service:8000")
_TIMEOUT_SECONDS = 3.0
_QUEUE: deque[tuple[str, str, dict]] = deque(maxlen=500)


def enabled() -> bool:
    return os.getenv("TERO_CUSTODY_DISABLED", "").strip().lower() not in ("1", "true", "yes")


def digest(obj) -> str:
    """Huella SHA-256 de un objeto (JSON canonico): sirve para anotar un evento sin copiarlo entero."""
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def _post(client: httpx.AsyncClient, service: str, organization_id: str | None, body: dict) -> bool:
    try:
        resp = await client.post(
            f"{CASE_SERVICE_URL}/internal/custody/events", json=body,
            headers=service_auth_headers(service, organization_id),
        )
    except httpx.HTTPError:
        return False
    if resp.status_code >= 500:
        return False
    if resp.status_code >= 400:
        logger.warning("case-service rechazo un evento de custodia (HTTP %s)", resp.status_code,
                       extra={"event_type": body.get("event_type"), "body": resp.text[:200]})
    return True  # entregado o rechazado definitivamente: reintentar no cambiaria nada


async def _deliver(service: str, organization_id: str | None, body: dict) -> bool:
    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
        pending = list(_QUEUE)
        remaining = []
        for item in pending[:20]:
            if not await _post(client, item[0], item[1] or None, item[2]):
                remaining.append(item)
        remaining.extend(pending[20:])
        _QUEUE.clear()
        _QUEUE.extend(remaining)
        return await _post(client, service, organization_id, body)


async def record_event(
    event_type: str, *, service: str, organization_id: str | None, actor: str = "", subject_type: str = "",
    subject_id: str = "", refs: list[str] | None = None, payload: dict | None = None,
) -> bool:
    """Anota un evento. Devuelve True si case-service lo recibio; False si quedo en cola o esta apagado."""
    if not enabled():
        return False
    body = {
        "event_type": event_type, "actor": actor, "source": service, "subject_type": subject_type,
        "subject_id": subject_id, "refs": refs or [], "payload": payload or {},
    }
    try:
        delivered = await asyncio.wait_for(_deliver(service, organization_id, body), timeout=_TIMEOUT_SECONDS * 2)
    except Exception as exc:  # noqa: BLE001 -- anotar evidencia jamas debe romper el flujo principal
        logger.warning("no se pudo anotar el evento de custodia: %s", exc, extra={"event_type": event_type})
        delivered = False
    if not delivered:
        if len(_QUEUE) == _QUEUE.maxlen:
            logger.error("cola de custodia llena: se descarta el evento mas viejo")
        _QUEUE.append((service, organization_id or "", body))
        logger.warning("evento de custodia en cola (case-service no respondio)", extra={"event_type": event_type})
    return delivered


def pending_events() -> int:
    return len(_QUEUE)
