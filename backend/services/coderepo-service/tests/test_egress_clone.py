"""Modo aislado: el escaneo programado no clona repositorios externos (y el mensaje lo explica)."""
import asyncio

import pytest

from app import services
from backend.shared import egress


def test_clone_blocked_in_isolated_mode(monkeypatch):
    monkeypatch.setenv("TERO_ISOLATED_MODE", "1")
    monkeypatch.delenv("TERO_EGRESS_ALLOW", raising=False)
    monkeypatch.setattr(services, "repo_url_safety_error", lambda url: None)
    egress.reset_for_tests()

    async def fake_exec(*a, **k):
        raise AssertionError("no deberia lanzar git")

    monkeypatch.setattr(services.asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(RuntimeError, match="modo aislado"):
        asyncio.run(services._clone_repo("https://github.com/acme/app.git", "main", "tok", "/tmp/nunca"))
    assert egress.pending()[0]["host"] == "github.com"
