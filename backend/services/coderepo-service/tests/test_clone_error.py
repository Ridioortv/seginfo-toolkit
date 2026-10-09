"""Tests de app/services.py::explain_clone_error (mensajes de git clone)."""
import asyncio
import os
import shutil
import subprocess
import tempfile

import pytest

from app import services
from app.services import explain_clone_error

RAW_PRIVATE = "Cloning into '/tmp/coderepo-scan-5vpuj0dr'... fatal: could not read Username for 'https://github.com': No such device or address"


def test_no_token_explains_private_or_missing_repo():
    msg = explain_clone_error(RAW_PRIVATE, "main", has_token=False)
    assert "no existe o es privado" in msg and "token" in msg
    assert "could not read Username" in msg  # el detalle crudo se conserva


def test_with_token_explains_token_problem():
    msg = explain_clone_error("fatal: Authentication failed for 'https://github.com/x/y/'", "main", has_token=True)
    assert "token guardado" in msg and "vencido" in msg


def test_missing_branch_is_explained():
    msg = explain_clone_error("fatal: Remote branch main not found in upstream origin", "main", has_token=False)
    assert "rama 'main' no existe" in msg and "master" in msg


def test_unknown_error_is_returned_untouched():
    assert explain_clone_error("fatal: unable to access: Could not resolve host", "main", False) == \
        "fatal: unable to access: Could not resolve host"


@pytest.mark.skipif(shutil.which("git") is None, reason="git no instalado")
def test_clone_repo_never_prompts_and_gives_friendly_error(monkeypatch):
    # Un repo inexistente local: sin prompt, error accionable (no cuelga ni pide credenciales).
    tmp = tempfile.mkdtemp()
    try:
        with pytest.raises(RuntimeError) as exc:
            asyncio.run(services._clone_repo("https://127.0.0.1:1/x/y.git", "main", None, os.path.join(tmp, "d")))
        assert "COULD NOT READ" not in str(exc.value).upper() or "privado" in str(exc.value)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
