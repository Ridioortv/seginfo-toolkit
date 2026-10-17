"""rate_limit: el cliente de Redis manda REDIS_PASSWORD (Redis ahora exige contrasena)."""
from backend.shared import rate_limit


def test_redis_client_gets_password_from_env(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr(rate_limit.aioredis, "Redis", Fake)
    monkeypatch.setattr(rate_limit, "_redis", None)
    monkeypatch.setenv("REDIS_PASSWORD", "s3cr3t-redis")
    rate_limit._get_redis()
    assert seen["password"] == "s3cr3t-redis"
    monkeypatch.setattr(rate_limit, "_redis", None)


def test_redis_client_without_password_is_none(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr(rate_limit.aioredis, "Redis", Fake)
    monkeypatch.setattr(rate_limit, "_redis", None)
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    rate_limit._get_redis()
    assert seen["password"] is None
    monkeypatch.setattr(rate_limit, "_redis", None)


def test_redis_ssl_flag(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr(rate_limit.aioredis, "Redis", Fake)
    monkeypatch.setattr(rate_limit, "_redis", None)
    monkeypatch.setenv("REDIS_SSL", "true")
    rate_limit._get_redis()
    assert seen["ssl"] is True
    monkeypatch.setattr(rate_limit, "_redis", None)
    monkeypatch.delenv("REDIS_SSL")
    rate_limit._get_redis()
    assert seen["ssl"] is False
    monkeypatch.setattr(rate_limit, "_redis", None)


def test_rate_limit_falls_back_to_memory_when_redis_is_down(monkeypatch):
    """Sin Redis ya no es fail-open total: el limite sigue aplicando (por proceso)."""
    import asyncio

    class Down:
        async def incr(self, *a, **k):
            raise ConnectionError("redis caido")

    monkeypatch.setattr(rate_limit, "_get_redis", lambda: Down())
    rate_limit._fallback_counts.clear()

    async def run():
        return [await rate_limit.check_rate_limit("login:ip:1.2.3.4", 3, 60) for _ in range(5)]

    assert asyncio.run(run()) == [True, True, True, False, False]
    # otra clave no se ve afectada
    assert asyncio.run(rate_limit.check_rate_limit("login:ip:9.9.9.9", 3, 60)) is True
