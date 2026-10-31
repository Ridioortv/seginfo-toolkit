"""Si la base todavia no esta lista al arrancar, el servicio espera y reintenta
en vez de morir con "socket.gaierror: Temporary failure in name resolution" /
"Application startup failed" (visto en una notebook, donde el primer arranque
de `docker compose up` tarda mas de un minuto)."""
import asyncio
import socket

import pytest

from backend.shared import database as dbmod


class _Conn:
    async def execute(self, _stmt):
        return None


class _FakeEngine:
    """engine.connect() que falla `failures` veces con `error` y despues anda."""

    def __init__(self, failures: int, error: Exception):
        self.failures = failures
        self.error = error
        self.calls = 0

    def connect(self):
        engine = self

        class _Ctx:
            async def __aenter__(self_inner):
                engine.calls += 1
                if engine.calls <= engine.failures:
                    raise engine.error
                return _Conn()

            async def __aexit__(self_inner, *exc):
                return False

        return _Ctx()


def _run(failures, error=None, **kwargs):
    error = error or socket.gaierror(-3, "Temporary failure in name resolution")
    fake = _FakeEngine(failures, error)
    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    dbmod.engine, original = fake, dbmod.engine
    try:
        asyncio.run(dbmod.wait_for_database(sleep=fake_sleep, **kwargs))
    finally:
        dbmod.engine = original
    return fake, sleeps


def test_ready_database_connects_at_once_without_waiting():
    fake, sleeps = _run(0)
    assert fake.calls == 1 and sleeps == []


def test_waits_and_retries_while_the_name_does_not_resolve():
    fake, sleeps = _run(3)  # el caso real: el host "postgres" todavia no resuelve
    assert fake.calls == 4
    assert sleeps == [3.0, 3.0, 3.0]


def test_gives_up_after_the_last_attempt_and_raises_the_real_error():
    error = socket.gaierror(-3, "Temporary failure in name resolution")
    fake = _FakeEngine(failures=99, error=error)
    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    original, dbmod.engine = dbmod.engine, fake
    try:
        with pytest.raises(socket.gaierror):
            asyncio.run(dbmod.wait_for_database(attempts=10, delay_seconds=3, sleep=fake_sleep))
    finally:
        dbmod.engine = original
    assert fake.calls == 10          # 10 intentos...
    assert len(sleeps) == 9          # ...con 9 esperas de 3 s entre ellos (no duerme despues del ultimo)


def test_other_startup_errors_are_retried_too():
    fake, _ = _run(2, error=ConnectionRefusedError("conexion rechazada"))
    assert fake.calls == 3


def test_defaults_are_ten_attempts_every_three_seconds():
    assert dbmod.DB_CONNECT_ATTEMPTS == 10 and dbmod.DB_CONNECT_DELAY_SECONDS == 3.0


def test_every_service_waits_for_the_database_before_creating_tables():
    """Regresion: ningun servicio debe volver a abrir engine.begin() sin esperar antes."""
    from pathlib import Path

    services = Path(__file__).resolve().parents[2]
    mains = sorted(services.glob("*/app/main.py"))
    if len(mains) < 15:
        pytest.skip("solo se ve este servicio (corriendo dentro de su contenedor)")
    for main in mains:
        src = main.read_text(encoding="utf-8")
        assert "wait_for_database" in src, main
        assert src.index("await wait_for_database()") < src.index("async with engine.begin() as conn:"), main


def test_every_service_dockerfile_has_a_healthcheck_start_period():
    from pathlib import Path

    services = Path(__file__).resolve().parents[2]
    dockerfiles = sorted(services.glob("*/Dockerfile"))
    if len(dockerfiles) < 15:
        pytest.skip("solo se ve este servicio (corriendo dentro de su contenedor)")
    for dockerfile in dockerfiles:
        src = dockerfile.read_text(encoding="utf-8")
        assert "HEALTHCHECK --start-period=90s --interval=10s --timeout=3s --retries=5" in src, dockerfile
