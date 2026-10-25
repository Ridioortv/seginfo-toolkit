"""Utilidades de los tests de gobernanza: SQLite en memoria y un repositorio git real temporal."""
import asyncio
import os
import subprocess

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import gov_models  # noqa: F401 -- registra las tablas
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


def make_repo(tmp_path, commits):
    """commits: lista de (mensaje, {ruta: contenido}, autor_nombre, autor_email). Devuelve la ruta del repo."""
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

    def git(*args, extra_env=None):
        subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, env={**env, **(extra_env or {})})

    git("init", "-q", "-b", "main")
    for i, (message, files, name, email) in enumerate(commits):
        for path, content in files.items():
            full = os.path.join(repo, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "a") as fh:
                fh.write(content)
        git("add", "-A")
        stamp = f"2026-10-0{i + 1}T10:00:00+00:00"
        git("-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-q", "-m", message,
            extra_env={"GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp})
    return repo
