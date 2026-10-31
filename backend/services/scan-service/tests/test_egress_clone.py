"""Modo aislado: no se clona un repositorio externo; uno interno si."""
import asyncio

from app.scanners import _codetarget
from backend.shared import egress


def test_clone_is_blocked_in_isolated_mode(monkeypatch):
    monkeypatch.setenv("TERO_ISOLATED_MODE", "1")
    monkeypatch.delenv("TERO_EGRESS_ALLOW", raising=False)
    egress.reset_for_tests()
    spawned = []

    async def fake_exec(*a, **k):
        spawned.append(a)
        raise AssertionError("no deberia lanzar git")

    monkeypatch.setattr(_codetarget.asyncio, "create_subprocess_exec", fake_exec)
    err = asyncio.run(_codetarget.clone_repo("https://x-access-token:SECRETO@github.com/acme/app.git", "/tmp/nunca"))
    assert err and "modo aislado" in err and "github.com" in err
    assert "SECRETO" not in err and spawned == []
    assert egress.pending()[0]["host"] == "github.com" and egress.pending()[0]["kind"] == "git"
