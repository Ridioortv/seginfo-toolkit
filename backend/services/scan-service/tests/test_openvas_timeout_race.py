"""Regression test para la race de asyncio+uvloop en el manejo de timeout
de gvm_query/probe_connection (app/scanners/openvas.py).

Encontrado corriendo contra un gvmd real (traceback real de produccion,
no hipotetico): cuando asyncio.wait_for(proc.communicate(), timeout=...)
expira, el handler de asyncio.TimeoutError llama proc.kill()
incondicionalmente. Si el subproceso gvm-cli ya termino/fue cosechado por
el event loop justo en la ventana entre el timeout disparando y ese
kill() ejecutandose, uvloop (a diferencia del event loop por default de
asyncio, que generalmente la absorbe en silencio) levanta
ProcessLookupError desde UVProcessTransport.kill() -> _check_proc(), que
antes se propagaba sin manejar: tiraba abajo con un 500 el
GET /openvas/status completo (via probe_connection), lo que dejaba
openvasReady en false para siempre del lado del frontend ("Activar
OpenVAS" no cargaba, y el scanner no aparecia en ningun dropdown).

Estos tests simulan esa race con un proceso falso cuyo .communicate()
tarda mas que el timeout (dispara TimeoutError) y cuyo .kill() levanta
ProcessLookupError (el proceso ya no existe), y verifican que ambas
funciones devuelven su tupla de error normal en vez de dejar escapar la
excepcion."""
import asyncio

import app.scanners.openvas as openvas


class _FakeProcAlreadyReaped:
    """Simula un gvm-cli que ya termino (fue cosechado) para cuando el
    event loop intenta matarlo tras el timeout."""

    returncode = -9

    def __init__(self):
        self.killed = False
        self.waited = False

    async def communicate(self):
        # Tarda mas que cualquier timeout razonable que le pasen los
        # tests de abajo -- fuerza a asyncio.wait_for a disparar
        # TimeoutError.
        await asyncio.sleep(10)
        return b"", b""  # pragma: no cover -- nunca se llega aca

    def kill(self):
        self.killed = True
        raise ProcessLookupError("ya no existe: el proceso se fue solo justo antes del kill()")

    async def wait(self):
        self.waited = True
        return self.returncode


def _patch_spawn(monkeypatch, fake_proc):
    async def fake_spawn(cmd):
        return fake_proc

    monkeypatch.setattr(openvas, "_spawn_gvm_cli", fake_spawn)


def test_gvm_query_survives_processlookuperror_on_timeout_kill(monkeypatch):
    fake_proc = _FakeProcAlreadyReaped()
    _patch_spawn(monkeypatch, fake_proc)

    rc, out, err = asyncio.run(
        openvas.gvm_query("/run/gvmd/gvmd.sock", "admin", "s3cret", "<get_tasks/>", timeout=0.01)
    )

    assert rc == -1
    assert out == ""
    assert "timeout" in err
    assert fake_proc.killed
    assert fake_proc.waited


def test_gvm_query_cancelled_error_survives_processlookuperror_on_kill(monkeypatch):
    fake_proc = _FakeProcAlreadyReaped()
    _patch_spawn(monkeypatch, fake_proc)

    async def _run_and_cancel():
        task = asyncio.ensure_future(
            openvas.gvm_query("/run/gvmd/gvmd.sock", "admin", "s3cret", "<get_tasks/>", timeout=60)
        )
        await asyncio.sleep(0)  # deja que gvm_query llegue a await proc.communicate()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run_and_cancel())

    assert fake_proc.killed
    assert fake_proc.waited


def test_probe_connection_survives_processlookuperror_on_timeout_kill(monkeypatch):
    fake_proc = _FakeProcAlreadyReaped()
    _patch_spawn(monkeypatch, fake_proc)
    monkeypatch.setattr(openvas.shutil, "which", lambda name: "/usr/bin/gvm-cli")

    ok, detail = asyncio.run(
        openvas.probe_connection("/run/gvmd/gvmd.sock", "admin", "s3cret", timeout=0.01)
    )

    assert ok is False
    assert "no hubo respuesta de gvmd" in detail
    assert fake_proc.killed
    assert fake_proc.waited
