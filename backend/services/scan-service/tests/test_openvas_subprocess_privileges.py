"""Tests puntuales del fix de "gvm-cli se niega a correr como root".

Encontrado corriendo el dashboard contra un gvmd REAL por primera vez
(hasta ahora todo se habia verificado con gvm_query mockeado, nunca
contra el binario real): gvm-tools (el paquete pip que da gvm-cli) tiene
una proteccion propia que aborta si se ejecuta como root (ver
gvmtools/helper.py::do_not_run_as_root -- "This tool MUST NOT be run as
root user."), y este contenedor corre como root (necesario para que los
caches de trivy/nuclei bajo /root, escritos en build-time, sigan siendo
escribibles en runtime -- ver Dockerfile). La solucion (_drop_priv_to_nobody
+ _spawn_gvm_cli en app/scanners/openvas.py) baja privilegios SOLO al
subproceso gvm-cli via preexec_fn, sin tocar el usuario del proceso
principal.

Estos tests verifican el WIRING (que create_subprocess_exec reciba el
preexec_fn correcto, y que ese preexec_fn llame setuid/setgid con el uid/
gid de "nobody") sin invocar de verdad setuid/setgid -- hacerlo de verdad
en un proceso que YA corre sin privilegios (como el que ejecuta estos
mismos tests en CI/sandbox) tiraria PermissionError, porque solo root
puede cambiar a un uid arbitrario."""
import asyncio

import app.scanners.openvas as openvas


def test_spawn_gvm_cli_passes_preexec_fn_to_drop_privileges():
    captured: dict = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return b"", b""

        return _FakeProc()

    original = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = fake_create_subprocess_exec
    try:
        asyncio.run(openvas._spawn_gvm_cli(["gvm-cli", "--help"]))
    finally:
        asyncio.create_subprocess_exec = original

    assert captured["args"] == ("gvm-cli", "--help")
    assert captured["kwargs"].get("preexec_fn") is openvas._drop_priv_to_nobody


def test_drop_priv_to_nobody_uses_nobody_uid_gid(monkeypatch):
    calls: list = []
    monkeypatch.setattr(openvas.os, "setgroups", lambda groups: calls.append(("setgroups", groups)))
    monkeypatch.setattr(openvas.os, "setgid", lambda gid: calls.append(("setgid", gid)))
    monkeypatch.setattr(openvas.os, "setuid", lambda uid: calls.append(("setuid", uid)))

    openvas._drop_priv_to_nobody()

    nobody = openvas.pwd.getpwnam("nobody")
    assert calls == [("setgroups", []), ("setgid", nobody.pw_gid), ("setuid", nobody.pw_uid)]


def test_gvm_query_and_probe_connection_both_use_shared_spawn_helper(monkeypatch):
    """Evita que un refactor futuro vuelva a duplicar el
    asyncio.create_subprocess_exec en dos lugares (perdiendo el
    preexec_fn en uno de ellos sin que ningun test lo note)."""
    calls: list = []

    async def fake_spawn(cmd):
        calls.append(cmd)

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return b"<get_version_response status='200'/>", b""

            def kill(self):
                pass

            async def wait(self):
                return None

        return _FakeProc()

    monkeypatch.setattr(openvas, "_spawn_gvm_cli", fake_spawn)
    monkeypatch.setattr(openvas.shutil, "which", lambda _name: "/usr/local/bin/gvm-cli")

    asyncio.run(openvas.gvm_query("/run/gvmd/gvmd.sock", "admin", "pw", "<get_version/>"))
    asyncio.run(openvas.probe_connection("/run/gvmd/gvmd.sock", "admin", "pw"))

    assert len(calls) == 2
