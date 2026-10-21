"""Shared async SQLAlchemy engine/session factory."""
import asyncio
import logging
import os
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger("database")

# Al levantar todo junto (`docker compose up`) un servicio puede arrancar antes
# de que Postgres acepte conexiones -- sobre todo en una notebook, donde el
# primer arranque tarda mas de un minuto. Sin reintentos el servicio moria con
# "socket.gaierror: Temporary failure in name resolution" / "Application startup
# failed" y quedaba caido. Ajustable con DB_CONNECT_ATTEMPTS / DB_CONNECT_DELAY_SECONDS.
DB_CONNECT_ATTEMPTS = int(os.getenv("DB_CONNECT_ATTEMPTS", "10"))
DB_CONNECT_DELAY_SECONDS = float(os.getenv("DB_CONNECT_DELAY_SECONDS", "3"))


def build_database_url() -> str:
    user = os.getenv("POSTGRES_USER", "sentinelops")
    password = os.getenv("POSTGRES_PASSWORD", "changeme")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "sentinelops")
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db}"


class Base(DeclarativeBase):
    pass


engine = create_async_engine(build_database_url(), pool_pre_ping=True, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def wait_for_database(attempts: int | None = None, delay_seconds: float | None = None, sleep=asyncio.sleep) -> None:
    """Espera a que la base acepte conexiones: hasta `attempts` intentos (10 por
    defecto) separados por `delay_seconds` (3 s). Se llama al principio del
    arranque (lifespan) de cada servicio, antes de crear tablas. Si se agotan los
    intentos, relanza el ultimo error (el servicio no arranca, como antes, pero
    despues de dar tiempo de verdad). `sleep` es inyectable para los tests."""
    attempts = DB_CONNECT_ATTEMPTS if attempts is None else attempts
    delay_seconds = DB_CONNECT_DELAY_SECONDS if delay_seconds is None else delay_seconds
    for attempt in range(1, max(attempts, 1) + 1):
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            if attempt > 1:
                logger.info("base de datos disponible (intento %d de %d)", attempt, attempts)
            return
        except Exception as exc:  # noqa: BLE001 -- DNS, conexion rechazada, "starting up", etc.
            if attempt >= attempts:
                logger.error("la base de datos no respondio tras %d intentos: %s", attempts, exc)
                raise
            logger.warning(
                "base de datos no disponible todavia (%s: %s) -- reintento %d/%d en %.0f s",
                type(exc).__name__, exc, attempt, attempts, delay_seconds,
            )
            await sleep(delay_seconds)


async def get_db():
    async with SessionLocal() as session:
        yield session
