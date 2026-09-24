"""Cliente OpenSearch compartido: almacena los eventos de log normalizados
(ECS-lite). Los metadatos estructurados (reglas Sigma, alertas) viven en
Postgres via SQLAlchemy, igual que el resto de los servicios."""
import os
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


def build_client() -> AsyncOpenSearch:
    host = os.getenv("OPENSEARCH_HOST", "opensearch")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))
    use_ssl = os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true"
    return AsyncOpenSearch(
        hosts=[{"host": host, "port": port}],
        http_compress=True,
        use_ssl=use_ssl,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=10,
    )


async def ensure_index(client: AsyncOpenSearch) -> None:
    if not await client.indices.exists(index=LOG_INDEX):
        await client.indices.create(index=LOG_INDEX, body=_INDEX_MAPPING)


async def index_event(client: AsyncOpenSearch, document: dict) -> str:
    result = await client.index(index=LOG_INDEX, body=document, refresh=False)
    return result["_id"]


async def search_events(client: AsyncOpenSearch, query: dict, size: int = 100) -> list[dict]:
    result = await client.search(index=LOG_INDEX, body={"query": query, "size": size, "sort": [{"@timestamp": "desc"}]})
    return [hit["_source"] | {"_id": hit["_id"]} for hit in result["hits"]["hits"]]
