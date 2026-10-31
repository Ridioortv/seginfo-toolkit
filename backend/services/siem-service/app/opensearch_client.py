"""Cliente OpenSearch compartido: almacena los eventos de log normalizados
(ECS-lite). Los metadatos estructurados (reglas Sigma, alertas) viven en
Postgres via SQLAlchemy, igual que el resto de los servicios."""
import os
import time

from opensearchpy import AsyncOpenSearch

LOG_INDEX = os.getenv("OPENSEARCH_LOG_INDEX", "sentinelops-logs")

_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "organization_id": {"type": "keyword"},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "source": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}}},
            "destination": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}}},
            "user": {"properties": {"name": {"type": "keyword"}}},
            "event": {
                "properties": {
                    "action": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "outcome": {"type": "keyword"},
                }
            },
            "message": {"type": "text"},
            "sentinelops": {
                "properties": {
                    "source_type": {"type": "keyword"},
                    "asset_id": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "raw": {"type": "text"},
                }
            },
        }
    }
}


# --- Disco lleno -------------------------------------------------------------------------------
# Cuando el disco de la PC pasa del 95 % (flood-stage), OpenSearch pone el indice en solo-lectura
# y rechaza TODAS las escrituras (HTTP 429/403 "cluster_block_exception"). Sin esto, el usuario
# veria un 500 generico y los logs se perderian sin explicacion.
DISK_FULL_MESSAGE = "El disco de la PC está casi lleno: OpenSearch dejó de aceptar logs. Liberá espacio."
DISK_FULL_PERCENT = 95.0
_DISK_MARKERS = (
    "read-only-allow-delete", "read_only_allow_delete", "flood-stage", "flood_stage",
    "cluster_block_exception", "disk usage exceeded", "forbidden/12",
)

# Momento (time.monotonic) en que una escritura fue rechazada por disco lleno; None = no se vio.
_disk_full_seen_at: float | None = None


class OpenSearchDiskFull(Exception):
    """OpenSearch rechazo una escritura porque el disco de la PC esta casi lleno."""


def is_disk_full_error(exc: BaseException) -> bool:
    """True si el error de OpenSearch es el bloqueo por disco lleno (y no otro 403/429)."""
    status_code = getattr(exc, "status_code", None)
    if status_code not in (403, 429):
        return False
    texto = " ".join(str(parte) for parte in (exc, getattr(exc, "error", ""), getattr(exc, "info", ""))).lower()
    return any(marca in texto for marca in _DISK_MARKERS)


def build_client() -> AsyncOpenSearch:
    host = os.getenv("OPENSEARCH_HOST", "opensearch")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))
    use_ssl = os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true"
    # Con la seguridad de OpenSearch activa hace falta usuario/contrasena.
    # verify_certs=False: el certificado es el interno de OpenSearch y el trafico
    # nunca sale de la red de Docker (el puerto solo se publica en 127.0.0.1).
    password = os.getenv("OPENSEARCH_ADMIN_PASSWORD") or os.getenv("OPENSEARCH_PASSWORD")
    auth = (os.getenv("OPENSEARCH_USER", "admin"), password) if password else None
    return AsyncOpenSearch(
        hosts=[{"host": host, "port": port}],
        http_compress=True,
        use_ssl=use_ssl,
        http_auth=auth,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=10,
    )


async def ensure_index(client: AsyncOpenSearch) -> None:
    if not await client.indices.exists(index=LOG_INDEX):
        await client.indices.create(index=LOG_INDEX, body=_INDEX_MAPPING)


async def index_event(client: AsyncOpenSearch, document: dict) -> str:
    global _disk_full_seen_at
    try:
        result = await client.index(index=LOG_INDEX, body=document, refresh=False)
    except Exception as exc:
        if is_disk_full_error(exc):
            _disk_full_seen_at = time.monotonic()
            raise OpenSearchDiskFull(DISK_FULL_MESSAGE) from exc
        raise
    _disk_full_seen_at = None   # una escritura volvio a funcionar: el espacio se libero
    return result["_id"]


async def storage_status(client: AsyncOpenSearch) -> dict:
    """Estado del almacenamiento de logs para el panel. disk_full=True si OpenSearch ya bloqueo las
    escrituras (indice en solo-lectura), si una escritura fue rechazada hace poco, o si el uso de
    disco ya pasa el umbral de bloqueo. Las consultas son de solo lectura: funcionan con el disco lleno."""
    blocked = False
    used_percent: float | None = None
    try:
        settings = await client.indices.get_settings(index=LOG_INDEX)
        for datos in settings.values():
            bloques = ((datos.get("settings") or {}).get("index") or {}).get("blocks") or {}
            if str(bloques.get("read_only_allow_delete", "")).lower() == "true":
                blocked = True
    except Exception:
        pass   # el indice todavia no existe o OpenSearch arranca: no es un problema de disco
    try:
        for nodo in await client.cat.allocation(format="json"):
            pct = nodo.get("disk.percent")
            if pct not in (None, ""):
                used_percent = max(used_percent or 0.0, float(pct))
    except Exception:
        pass
    disk_full = blocked or _disk_full_seen_at is not None or (used_percent or 0.0) >= DISK_FULL_PERCENT
    return {
        "writable": not disk_full,
        "disk_full": disk_full,
        "disk_used_percent": used_percent,
        "message": DISK_FULL_MESSAGE if disk_full else None,
    }


async def search_events(client: AsyncOpenSearch, query: dict, size: int = 100) -> list[dict]:
    result = await client.search(index=LOG_INDEX, body={"query": query, "size": size, "sort": [{"@timestamp": "desc"}]})
    return [hit["_source"] | {"_id": hit["_id"]} for hit in result["hits"]["hits"]]
