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

Fail-open a proposito: si Redis no esta disponible (arranque en el orden
equivocado, un problema transitorio de red), este modulo deja pasar el
request en vez de tirar 500/503 en todo el login -- un rate limiter es
defensa en profundidad, no el control principal (eso son el hash de
password + MFA), y no tiene sentido que una falla de infraestructura en
Redis se traduzca en que nadie pueda entrar a la plataforma."""
import logging
import os
import time

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
            socket_connect_timeout=2, socket_timeout=2,
        )
    return _redis


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
        logger.warning("rate limiter: Redis no disponible, dejando pasar el request (fail-open)")
        return True
