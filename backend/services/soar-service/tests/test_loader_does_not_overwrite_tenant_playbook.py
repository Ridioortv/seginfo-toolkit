import asyncio
from pathlib import Path
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
from app import playbook_loader
from app.models import Base, Playbook


def test_yaml_sync_never_overwrites_tenant_owned_playbook(tmp_path, monkeypatch):
    (tmp_path / "x.yaml").write_text("name: Mio\ndescription: YAML\nsteps: [{type: noop}]\n", encoding="utf-8")
    monkeypatch.setattr(playbook_loader, "PLAYBOOKS_DIR", Path(tmp_path))

    async def run():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            db.add(Playbook(name="Mio", organization_id="org-a", description="del tenant", steps=[]))
            await db.flush()
            await playbook_loader.sync_playbooks_from_yaml(db)
            row = (await db.execute(Playbook.__table__.select())).first()
            description = row.description
        await engine.dispose()
        return description

    assert asyncio.run(run()) == "del tenant"


def test_playbook_names_are_unique_per_organization_not_global(tmp_path, monkeypatch):
    """El 409 por nombre ya no filtra que OTRO tenant usa ese nombre, y una plantilla
    built-in convive con un playbook de tenant del mismo nombre."""
    from sqlalchemy.exc import IntegrityError
    (tmp_path / "x.yaml").write_text("name: Mio\ndescription: YAML\nsteps: [{type: noop}]\n", encoding="utf-8")
    monkeypatch.setattr(playbook_loader, "PLAYBOOKS_DIR", Path(tmp_path))

    async def run():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            db.add(Playbook(name="Mio", organization_id="org-a", description="A", steps=[]))
            db.add(Playbook(name="Mio", organization_id="org-b", description="B", steps=[]))  # otro tenant: permitido
            await db.flush()
            await playbook_loader.sync_playbooks_from_yaml(db)  # built-in "Mio" (org NULL) convive
            await playbook_loader.sync_playbooks_from_yaml(db)  # idempotente
            rows = (await db.execute(Playbook.__table__.select())).all()
            assert sorted((r.organization_id or "", r.description) for r in rows) == [("", "YAML"), ("org-a", "A"), ("org-b", "B")]
            db.add(Playbook(name="Mio", organization_id="org-a", description="dup", steps=[]))
            with pytest.raises(IntegrityError):
                await db.flush()
        await engine.dispose()

    asyncio.run(run())
