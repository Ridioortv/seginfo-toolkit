"""Rate limiting (ventana fija) respaldado por Redis, para endpoints
sensibles a fuerza bruta -- login, confirmacion de MFA, login con Google.

Redis ya estaba provisionado en docker-compose.yml (servicio `redis`, con
REDIS_HOST inyectado a cada microservicio) pero nada lo usaba todavia --
era infraestructura "de fabrica" sin ninguna feature real detras. Sin
limite de intentos, /auth/login se puede atacar por fuerza bruta de
password (o de codigo TOTP, con valid_window=1 solo hay ~3 codigos validos
en cada momento pero igual son pocas combinaciones para probar sin
limite) a la velocidad que permita la red, sin que quede ninguna señal
mas alla de las metricas de Prometheus.

Si Redis no esta disponible (arranque en el orden equivocado, un problema
transitorio de red) NO se tira 500/503 en todo el login ni se deja el
endpoint sin limite: se usa un contador en memoria del proceso (por
proceso, asi que con varias replicas el limite efectivo es mayor, pero la
fuerza bruta sostenida contra un proceso sigue frenada). Antes era
fail-open total: tirando Redis abajo se desactivaba el limite de intentos."""
import logging
import os
import time
from collections import OrderedDict

import redis.asyncio as aioredis

logger = logging.getLogger("rate_limit")

_redis: aioredis.Redis | None = None


def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        host = os.getenv("REDIS_HOST", "redis")
        port = int(os.getenv("REDIS_PORT", "6379"))
        _redis = aioredis.Redis(
            host=host, port=port, decode_responses=True,
            password=os.getenv("REDIS_PASSWORD") or None,
            # REDIS_SSL=true para Redis gestionado con cifrado en transito (ElastiCache).
            ssl=os.getenv("REDIS_SSL", "false").lower() == "true",
            socket_connect_timeout=2, socket_timeout=2,
        )
    return _redis


# Respaldo en memoria cuando Redis no responde: {(key, bucket): intentos}, acotado.
_FALLBACK_MAX_KEYS = 50_000
_fallback_counts: "OrderedDict[tuple[str, int], int]" = OrderedDict()


def _check_in_memory(key: str, limit: int, window_seconds: int) -> bool:
    bucket = int(time.time() // window_seconds)
    k = (key, bucket)
    count = _fallback_counts.get(k, 0) + 1
    _fallback_counts[k] = count
    _fallback_counts.move_to_end(k)
    while len(_fallback_counts) > _FALLBACK_MAX_KEYS:
        _fallback_counts.popitem(last=False)
    return count <= limit


async def check_rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """True si el request esta permitido, False si la key ya supero
    `limit` intentos en la ventana actual. Ventana fija (no deslizante):
    simple y suficiente para frenar fuerza bruta sostenida sin necesitar
    un script Lua para hacerla atomica de punta a punta."""
    try:
        r = _get_redis()
        bucket = int(time.time() // window_seconds)
        redis_key = f"ratelimit:{key}:{bucket}"
        count = await r.incr(redis_key)
        if count == 1:
            await r.expire(redis_key, window_seconds)
        return count <= limit
    except Exception:
        logger.warning("rate limiter: Redis no disponible, usando el contador en memoria del proceso")
        return _check_in_memory(key, limit, window_seconds)
