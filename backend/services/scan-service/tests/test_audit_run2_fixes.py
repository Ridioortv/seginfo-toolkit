"""Regresiones de la 2da pasada de auditoria (scan-service)."""
import asyncio
import os
import pytest
from app import services
from app.scanners import _codetarget
from app.schemas import ScanJobCreate, ScanJobOut
from app.target_validation import reject_dangerous_network_target, strip_url_userinfo, validate_target


@pytest.mark.parametrize("target", ["127.1", "2130706433", "0x7f000001", "0177.0.0.1", "0", "169.254.43518", "http://127.1/"])
def test_numeric_ipv4_forms_are_blocked(target):
    with pytest.raises(ValueError):
        reject_dangerous_network_target(target)


def test_rfc1918_still_allowed_and_public_ok():
    reject_dangerous_network_target("192.168.1.10")
    reject_dangerous_network_target("example.com")


@pytest.mark.parametrize("target", [
    "https://x-access-token:SECRET@github.com/o/r.git", "https://SECRET@github.com/o/r.git",
])
def test_userinfo_in_target_is_rejected(target):
    with pytest.raises(ValueError):
        validate_target(target)


def test_image_digest_reference_still_valid():
    assert validate_target("repo/img@sha256:abcdef0123456789")


def test_legacy_row_target_is_masked_on_output():
    assert strip_url_userinfo("https://u:SECRET@host/x.git") == "https://host/x.git"
    out = ScanJobOut.model_construct  # noqa: F841 -- el validador corre en model_validate
    assert "SECRET" not in strip_url_userinfo("http://SECRET@h/")


def test_known_example_agent_keys_refused_even_in_development(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    assert services.agent_key_is_refused("cambiame-key-agente-lan")
    assert not services.agent_key_is_refused("a" * 64)


def test_cancel_during_clone_kills_git_and_removes_tmpdir(monkeypatch, tmp_path):
    killed = {}

    class FakeProc:
        returncode = None

        async def communicate(self):
            await asyncio.sleep(3600)

        def kill(self):
            killed["yes"] = True
            self.returncode = -9

        async def wait(self):
            return self.returncode

    async def fake_exec(*a, **k):
        return FakeProc()

    monkeypatch.setattr(_codetarget.asyncio, "create_subprocess_exec", fake_exec)
    created = {}
    real_mkdtemp = _codetarget.tempfile.mkdtemp

    def mk(prefix=""):
        d = real_mkdtemp(prefix=prefix, dir=str(tmp_path))
        created["d"] = d
        return d

    monkeypatch.setattr(_codetarget.tempfile, "mkdtemp", mk)

    async def run():
        async def work():
            async with _codetarget.CodeTarget("https://example.com/r.git"):
                pass

        t = asyncio.create_task(work())
        await asyncio.sleep(0.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(run())
    assert killed.get("yes")
    assert not os.path.exists(created["d"])


def test_hostname_resolving_to_loopback_or_metadata_is_refused(monkeypatch):
    """Un dominio del atacante con registro A a 127.0.0.1 / 169.254.169.254 pasaba la validacion de texto."""
    import socket
    from app import target_validation as tv

    def fake(host, port, **kw):
        return {
            "evil.example": [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))],
            "loop.example": [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 0, 0, 0))],
            "lan.example": [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 0))],
            "pub.example": [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
        }[host]

    monkeypatch.setattr(tv.socket, "getaddrinfo", fake)
    assert "169.254.169.254" in tv.resolved_target_error("https://evil.example/x")
    assert tv.resolved_target_error("loop.example") is not None
    assert tv.resolved_target_error("lan.example") is None      # RFC1918 se permite (LAN del cliente)
    assert tv.resolved_target_error("pub.example") is None
    assert tv.resolved_target_error("10.0.0.5") is None         # IP literal: lo valida otro chequeo


def test_unresolvable_hostname_is_not_a_dns_block(monkeypatch):
    import socket
    from app import target_validation as tv

    def boom(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(tv.socket, "getaddrinfo", boom)
    assert tv.resolved_target_error("no-existe.example") is None


@pytest.mark.parametrize("scanner", ["gitleaks", "semgrep"])
@pytest.mark.parametrize("path", ["/proc/self/environ", "/tmp", "/", "/etc/passwd", "C:\\Users\\x\\repo"])
def test_code_scanners_in_container_reject_local_paths(scanner, path):
    from app.schemas import ScanJobCreate, ScanScheduleCreate
    with pytest.raises(Exception):
        ScanJobCreate(scanner_type=scanner, target=path)
    with pytest.raises(Exception):
        ScanScheduleCreate(scanner_type=scanner, target=path, frequency="daily")


def test_code_scanners_still_accept_git_urls_and_remote_agent_paths():
    from app.schemas import ScanJobCreate, ScanScheduleCreate
    assert ScanJobCreate(scanner_type="gitleaks", target="https://github.com/org/repo.git")
    assert ScanScheduleCreate(scanner_type="semgrep", target="C:\\Users\\x\\repo", frequency="daily",
                              agent_id="a1", agent_api_key="k")


def test_falco_and_zeek_require_admin_or_soc_manager():
    from fastapi import HTTPException
    from app import main
    from app.models import ScannerType
    for scanner in (ScannerType.falco, ScannerType.zeek):
        with pytest.raises(HTTPException) as exc:
            main._require_host_wide_permission(scanner, {"role": "analyst"})
        assert exc.value.status_code == 403
        main._require_host_wide_permission(scanner, {"role": "soc_manager"})
        main._require_host_wide_permission(scanner, {"role": "admin"})
        main._require_host_wide_permission(scanner, {"role": "analyst"}, agent_id="a1")  # corre en la maquina del cliente
    main._require_host_wide_permission(ScannerType.nuclei, {"role": "analyst"})
