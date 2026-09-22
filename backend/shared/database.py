"""Shared async SQLAlchemy engine/session factory."""
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase


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


async def get_db():
    async with SessionLocal() as session:
        yield session
