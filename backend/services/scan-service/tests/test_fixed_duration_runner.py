"""La ventana fija de Falco/Zeek la controla el codigo, no solo el flag del programa:
un programa que ignora su propio -M igual se corta al vencer y se conserva lo capturado."""
import asyncio
import sys
import time

from app.scanners import falco
from app.scanners._duration import run_for_fixed_duration

STUBBORN = (
    "import time,sys; print('{\"rule\":\"R\",\"output\":\"evento\",\"priority\":\"warning\"}', flush=True); time.sleep(120)"
)


def test_program_that_ignores_its_own_stop_is_cut_and_output_is_kept():
    t0 = time.time()
    code, out, err, stopped = asyncio.run(run_for_fixed_duration([sys.executable, "-c", STUBBORN], 1, grace_seconds=5))
    assert stopped is True
    assert b"evento" in out
    assert time.time() - t0 < 15  # no espero los 120 s


def test_program_that_ends_by_itself_is_not_marked_as_cut():
    code, out, err, stopped = asyncio.run(
        run_for_fixed_duration([sys.executable, "-c", "print('listo')"], 5)
    )
    assert (code, stopped) == (0, False) and b"listo" in out


def test_missing_binary_raises_file_not_found():
    try:
        asyncio.run(run_for_fixed_duration(["no-existe-este-binario-xyz"], 1))
    except FileNotFoundError:
        return
    raise AssertionError("tenia que levantar FileNotFoundError")


def test_falco_driver_returns_findings_even_when_it_has_to_be_stopped(monkeypatch):
    async def fake_runner(cmd, duration_seconds, grace_seconds=10):
        assert cmd[:3] == ["falco", "-M", "60"]
        line = '{"rule":"Terminal shell in container","output":"x","priority":"Warning"}\n'
        return -15, line.encode(), b"", True

    monkeypatch.setattr(falco, "run_for_fixed_duration", fake_runner)
    result = asyncio.run(falco.FalcoDriver().run("host", {"duration_minutes": 1}))
    assert result.error is None or result.error == ""
    assert len(result.findings) == 1


def test_falco_driver_reports_startup_failure(monkeypatch):
    async def fake_runner(cmd, duration_seconds, grace_seconds=10):
        return 1, b"", b"Operation not permitted", False

    monkeypatch.setattr(falco, "run_for_fixed_duration", fake_runner)
    result = asyncio.run(falco.FalcoDriver().run("host", {}))
    assert "no pudo arrancar" in result.error
