"""Regresion: un scanner que sale con codigo != 0 y SIN salida es un FALLO, no
"0 hallazgos".

Bug real (verificado corriendo los binarios): nuclei y trivy salen con codigo 1
ante un error fatal ("no templates provided for scan", "--skip-db-update cannot
be specified on the first run"), con stdout vacio. Los drivers aceptaban el 1
como "hubo hallazgos", asi que el job terminaba COMPLETADO con 0 hallazgos
(peor que un error: el usuario creia que el objetivo estaba limpio). Estos tests
fijan el comportamiento correcto sin necesitar los binarios (se simula el
subproceso)."""
import asyncio
import json

import pytest

from app.scanners import base, nuclei, semgrep, trivy
from app.scanners.base import clean_stderr


class _FakeProc:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self._out, self._err = stdout, stderr

    async def communicate(self):
        return self._out, self._err

    def kill(self):
        pass

    async def wait(self):
        return self.returncode


def _patch_exec(monkeypatch, module, procs: list, calls: list | None = None):
    queue = list(procs)

    async def fake_exec(*cmd, **kwargs):
        if calls is not None:
            calls.append(list(cmd))
        return queue.pop(0)

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", fake_exec)


_NUCLEI_FINDING = json.dumps({"template-id": "t", "info": {"name": "Hallazgo", "severity": "low"}, "matched-at": "http://x"})
_ANSI = b"\x1b[1;31mFTL\x1b[0m] Could not run nuclei: no templates provided for scan"


class TestNucleiExitCodes:
    def test_fatal_exit_1_with_empty_stdout_is_an_error_not_zero_findings(self, monkeypatch):
        _patch_exec(monkeypatch, nuclei, [_FakeProc(1, b"", _ANSI)])
        result = asyncio.run(nuclei.NucleiDriver().run("http://10.0.0.5", {}))
        assert result.error
        assert "plantillas" in result.error
        assert "\x1b" not in result.error  # sin codigos de color ANSI

    def test_exit_0_without_output_is_a_clean_scan(self, monkeypatch):
        _patch_exec(monkeypatch, nuclei, [_FakeProc(0, b"", b"")])
        result = asyncio.run(nuclei.NucleiDriver().run("http://10.0.0.5", {}))
        assert result.error is None and result.findings == []

    def test_exit_1_with_output_still_parses_findings(self, monkeypatch):
        _patch_exec(monkeypatch, nuclei, [_FakeProc(1, _NUCLEI_FINDING.encode(), b"")])
        result = asyncio.run(nuclei.NucleiDriver().run("http://10.0.0.5", {}))
        assert result.error is None and len(result.findings) == 1

    def test_unknown_failure_without_stderr_still_reports_the_exit_code(self, monkeypatch):
        _patch_exec(monkeypatch, nuclei, [_FakeProc(2, b"", b"")])
        result = asyncio.run(nuclei.NucleiDriver().run("http://10.0.0.5", {}))
        assert result.error and "2" in result.error


class TestTrivyExitCodes:
    def test_fatal_exit_1_is_an_error(self, monkeypatch):
        _patch_exec(monkeypatch, trivy, [_FakeProc(1, b"", b"FATAL init error: permission denied")])
        result = asyncio.run(trivy.TrivyDriver().run("postgres:16", {}))
        assert result.error and "permission denied" in result.error
        assert result.findings == []

    def test_first_run_without_db_retries_without_skip_flags_and_succeeds(self, monkeypatch):
        calls: list = []
        fatal = b"FATAL DB error: database error: --skip-db-update cannot be specified on the first run"
        ok = json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "p", "Severity": "HIGH"}]}]}).encode()
        _patch_exec(monkeypatch, trivy, [_FakeProc(1, b"", fatal), _FakeProc(0, ok, b"")], calls)
        result = asyncio.run(trivy.TrivyDriver().run("postgres:16", {}))
        assert result.error is None
        assert len(result.findings) == 1
        assert "--skip-db-update" in calls[0]
        assert "--skip-db-update" not in calls[1] and "--skip-java-db-update" not in calls[1]

    def test_retry_failure_is_reported(self, monkeypatch):
        fatal = b"FATAL DB error: --skip-db-update cannot be specified on the first run"
        _patch_exec(monkeypatch, trivy, [_FakeProc(1, b"", fatal), _FakeProc(1, b"", b"FATAL failed to download vulnerability DB")])
        result = asyncio.run(trivy.TrivyDriver().run("postgres:16", {}))
        assert result.error and "download" in result.error

    def test_exit_0_parses_findings(self, monkeypatch):
        ok = json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2", "PkgName": "p", "Severity": "LOW"}]}]}).encode()
        _patch_exec(monkeypatch, trivy, [_FakeProc(0, ok, b"")])
        result = asyncio.run(trivy.TrivyDriver().run("postgres:16", {}))
        assert result.error is None and result.findings[0]["cve_id"] == "CVE-2"


class TestSemgrepExitCodes:
    def test_exit_1_with_empty_stdout_is_an_error(self, monkeypatch, tmp_path):
        _patch_exec(monkeypatch, semgrep, [_FakeProc(1, b"", b"semgrep: error: algo salio mal")])
        result = asyncio.run(semgrep.SemgrepDriver().run(str(tmp_path), {}))
        assert result.error and "algo salio mal" in result.error

    def test_exit_2_is_an_error(self, monkeypatch, tmp_path):
        _patch_exec(monkeypatch, semgrep, [_FakeProc(2, b"{}", b"fatal")])
        result = asyncio.run(semgrep.SemgrepDriver().run(str(tmp_path), {}))
        assert result.error

    def test_rule_id_drops_the_rules_directory_prefix(self):
        raw = json.dumps({"results": [{
            "check_id": "opt.sentinelops-semgrep-rules.sentinelops-python-eval-exec",
            "path": "app.py", "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "m"},
        }]})
        finding = semgrep.parse_semgrep_json(raw)[0]
        assert finding["rule_id"] == "sentinelops-python-eval-exec"
        assert finding["title"].startswith("sentinelops-python-eval-exec en ")


class TestCleanStderr:
    def test_strips_ansi_color_codes(self):
        assert clean_stderr("\x1b[1;31mFTL\x1b[0m] boom") == "FTL] boom"

    def test_truncates(self):
        assert len(clean_stderr("x" * 5000, limit=100)) <= 100

    def test_permission_denied_adds_the_fix_recipe(self):
        out = clean_stderr("open /root/.cache/trivy/fanal: permission denied")
        assert "chown -R sentinelops" in out
        assert len(out) <= 2000
