"""Utilidades de los tests de custodia: SQLite en archivo temporal y una app con la DB sustituida."""
import asyncio
import os
import tempfile

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import custody_models  # noqa: F401
from app.models import Base


def run_db(coro_fn):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async def main():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            return await coro_fn(factory)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def file_db():
    path = os.path.join(tempfile.mkdtemp(prefix="custody-"), "t.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(setup())
    return engine, Session
