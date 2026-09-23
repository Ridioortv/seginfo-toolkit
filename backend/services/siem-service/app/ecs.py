"""Normalizacion de eventos de log al subconjunto de Elastic Common Schema
(ECS) que usa SentinelOps. Es pura transformacion de datos declarados por el
cliente que ingesta (agentes, forwarders, APIs) -- nunca se ejecuta nada."""
from datetime import datetime, timezone


def normalize_event(raw: dict, organization_id: str = "") -> dict:
    """Convierte un evento de entrada (campos sueltos, ver schemas.LogEventIn)
    en un documento ECS-lite listo para indexar en OpenSearch.
    organization_id se guarda como campo propio (no parte del estandar ECS)
    para poder filtrar por tenant en cada busqueda -- ver
    opensearch_client.py, search_events."""
    timestamp = raw.get("timestamp") or datetime.now(timezone.utc).isoformat()

    return {
        "@timestamp": timestamp,
        "organization_id": organization_id,
        "host": {"name": raw.get("host") or ""},
        "source": {"ip": raw.get("source_ip") or ""},
        "destination": {"ip": raw.get("dest_ip") or ""},
        "user": {"name": raw.get("user") or ""},
        "event": {
            "action": raw.get("event_action") or "",
            "category": raw.get("event_category") or "",
            "outcome": raw.get("event_outcome") or "",
        },
        "message": raw.get("message") or "",
        "sentinelops": {
            "source_type": raw.get("source_type") or "generic",
            "asset_id": raw.get("asset_id"),
            "raw": raw.get("raw") or "",
        },
    }


def get_by_path(document: dict, dotted_path: str):
    """Recorre un dict anidado siguiendo un path 'event.action' -> document['event']['action']."""
    node = document
    for part in dotted_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node
