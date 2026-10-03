"""Tests para app/scanners/_codetarget.py (helper compartido por
semgrep/gitleaks): resolucion de target a path local, sin clonar un
repo real (salvo el caso explicito de URL invalida, que falla rapido
sin red)."""
import pytest
from app.scanners._codetarget import CodeTarget, is_clonable_url, _redact


def test_is_clonable_url_detects_http_https():
    assert is_clonable_url("https://github.com/org/repo.git")
    assert is_clonable_url("http://gitlab.local/org/repo.git")


def test_is_clonable_url_rejects_local_paths():
    assert not is_clonable_url("/home/user/repo")
    assert not is_clonable_url("C:\\Users\\manu\\repo")


def test_redact_hides_embedded_token():
    redacted = _redact("https://x-access-token:ghp_SECRETO@github.com/org/repo.git")
    assert "ghp_SECRETO" not in redacted
    assert "***@github.com" in redacted


@pytest.mark.asyncio
async def test_codetarget_uses_existing_local_directory(tmp_path):
    async with CodeTarget(str(tmp_path)) as ct:
        assert ct.error is None
        assert ct.path == str(tmp_path)


@pytest.mark.asyncio
async def test_codetarget_nonexistent_path_and_not_url_is_error():
    async with CodeTarget("/esto/no/existe/en/ningun/lado") as ct:
        assert ct.error is not None
        assert ct.path is None


@pytest.mark.asyncio
async def test_codetarget_invalid_clone_url_reports_clear_error():
    async with CodeTarget("https://este-dominio-no-existe-sentinelops.invalid/repo.git", clone_timeout=15) as ct:
        assert ct.error is not None
        assert "no se pudo clonar" in ct.error
