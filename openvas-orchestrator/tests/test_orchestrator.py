"""Tests de openvas-orchestrator/main.py -- SIN Docker real (este entorno
no tiene acceso al Docker Desktop de la maquina donde corre el stack).
Las funciones puras (_classify_container, _parse_compose_ps_json,
_progress_from_ps, _sync_percent, _render_env_lines) se testean con
entradas fabricadas; el flujo completo (_run_activation) se testea
mockeando _run_compose y _spawn_compose_up con los fakes de mas abajo
(FakeProc/FakeStream), que imitan lo suficiente de subprocess.run /
asyncio.subprocess.Process como para ejercitar el codigo real sin gastar
tiempo ni necesitar un daemon Docker."""
import asyncio
import json

import main as orch


# ---- _classify_container ----

def test_classify_exited_zero_is_done():
    assert orch._classify_container({"State": "exited", "ExitCode": 0}) == "done"


def test_classify_exited_nonzero_is_failed():
    assert orch._classify_container({"State": "exited", "ExitCode": 1}) == "failed"


def test_classify_healthy_is_done():
    assert orch._classify_container({"State": "running", "Health": "healthy"}) == "done"


def test_classify_unhealthy_is_failed():
    assert orch._classify_container({"State": "running", "Health": "unhealthy"}) == "failed"


def test_classify_running_no_healthcheck_is_done():
    assert orch._classify_container({"State": "running", "Health": ""}) == "done"


def test_classify_starting_is_pending():
    assert orch._classify_container({"State": "running", "Health": "starting"}) == "pending"


def test_classify_created_is_pending():
    assert orch._classify_container({"State": "created", "Health": ""}) == "pending"


# ---- _parse_compose_ps_json ----

def test_parse_ps_json_array():
    stdout = json.dumps([{"Service": "gvmd", "State": "running", "Health": "healthy"}])
    entries = orch._parse_compose_ps_json(stdout)
    assert len(entries) == 1 and entries[0]["Service"] == "gvmd"


def test_parse_ps_json_single_object():
    stdout = json.dumps({"Service": "gvmd", "State": "running"})
    entries = orch._parse_compose_ps_json(stdout)
    assert len(entries) == 1


def test_parse_ps_jsonl():
    stdout = (
        json.dumps({"Service": "gvmd", "State": "running", "Health": "healthy"}) + "\n" +
        json.dumps({"Service": "scap-data", "State": "running", "Health": "starting"})
    )
    entries = orch._parse_compose_ps_json(stdout)
    assert len(entries) == 2
    assert {e["Service"] for e in entries} == {"gvmd", "scap-data"}


def test_parse_ps_empty():
    assert orch._parse_compose_ps_json("") == []
    assert orch._parse_compose_ps_json("   ") == []


# ---- _progress_from_ps / _sync_percent ----

def _entry(service, state="running", health="healthy", exit_code=None):
    e = {"Service": service, "State": state}
    if health is not None:
        e["Health"] = health
    if exit_code is not None:
        e["ExitCode"] = exit_code
    return e


def test_progress_none_started_yet():
    done, total, failed = orch._progress_from_ps("[]")
    assert done == 0
    assert total == len(orch.OPENVAS_SERVICES)
    assert failed == []
    assert orch._sync_percent(done, total) == 5


def test_progress_all_done():
    entries = [_entry(name) for name in orch.OPENVAS_SERVICES]
    stdout = json.dumps(entries)
    done, total, failed = orch._progress_from_ps(stdout)
    assert done == total == len(orch.OPENVAS_SERVICES)
    assert failed == []
    assert orch._sync_percent(done, total) == 90


def test_progress_partial():
    half = orch.OPENVAS_SERVICES[: len(orch.OPENVAS_SERVICES) // 2]
    entries = [_entry(name) for name in half]
    stdout = json.dumps(entries)
    done, total, failed = orch._progress_from_ps(stdout)
    assert done == len(half)
    assert total == len(orch.OPENVAS_SERVICES)
    pct = orch._sync_percent(done, total)
    assert 5 < pct < 90


def test_progress_reports_failed_container():
    entries = [_entry(name) for name in orch.OPENVAS_SERVICES if name != "scap-data"]
    entries.append(_entry("scap-data", state="exited", health=None, exit_code=1))
    stdout = json.dumps(entries)
    done, total, failed = orch._progress_from_ps(stdout)
    assert failed == ["scap-data"]


# ---- .env read/render ----

def test_render_env_lines_updates_existing_and_appends_new():
    original = ["POSTGRES_USER=sentinelops", "GVM_USER=old", "# comment", "GVM_SOCKET_PATH=/run/gvmd/gvmd.sock"]
    rendered = orch._render_env_lines(original, {"GVM_USER": "admin", "GVM_PASSWORD": "s3cr3t"})
    assert "GVM_USER=admin" in rendered
    assert "GVM_PASSWORD=s3cr3t" in rendered
    assert "POSTGRES_USER=sentinelops" in rendered
    assert "# comment" in rendered
    assert rendered.count("GVM_USER=admin") == 1
    assert not any(l.startswith("GVM_USER=old") for l in rendered)
    assert rendered[-1] == "GVM_PASSWORD=s3cr3t"


def test_render_env_lines_empty_file():
    rendered = orch._render_env_lines([], {"GVM_USER": "admin"})
    assert rendered == ["GVM_USER=admin"]


# ---- Fakes para _spawn_compose_up (proceso de "up -d" en 2do plano) ----

class FakeStream:
    """Imita un StreamReader de asyncio: una sola lectura devuelve todos
    los bytes fabricados, la siguiente devuelve b"" (EOF) -- alcanza para
    ejercitar _drain_stream sin un pipe real."""

    def __init__(self, data: bytes = b""):
        self._data = data
        self._sent = False

    async def read(self, n: int) -> bytes:
        if self._sent:
            return b""
        self._sent = True
        return self._data


class FakeProc:
    """Imita un asyncio.subprocess.Process lo suficiente para
    _run_activation: .wait() tarda `delay_ticks` "vueltas" (cada una una
    resincronizacion del event loop) antes de resolver a `returncode`, o
    -- con never_finishes=True -- se queda esperando indefinidamente (sin
    gastar CPU: un asyncio.Event que nunca se setea) para simular que el
    proceso jamas termina dentro de la ventana del test. .kill() se puede
    verificar despues via `.killed`."""

    def __init__(self, returncode: int = 0, stdout_data: bytes = b"", delay_ticks: int = 0, never_finishes: bool = False):
        self.returncode = None
        self._final_returncode = returncode
        self._delay_ticks = delay_ticks
        self._never_finishes = never_finishes
        self._killed_event = asyncio.Event()
        self.stdout = FakeStream(stdout_data)
        self.killed = False

    async def wait(self) -> int:
        if self._never_finishes:
            # Como un proceso real: no vuelve solo, pero SI vuelve una
            # vez que lo matan (ver kill() abajo) -- asi no queda una
            # task huerfana esperando para siempre cuando el codigo bajo
            # test llama a kill() y despues termina.
            await self._killed_event.wait()
            return self.returncode
        for _ in range(self._delay_ticks):
            await asyncio.sleep(0)
        self.returncode = self._final_returncode
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self._killed_event.set()


async def _async_return(value):
    return value


def _patch_common(names):
    """Guarda los valores originales de los globals que se van a
    mockear, para poder restaurarlos en el finally de cada test."""
    return {name: getattr(orch, name) for name in names}


def _restore(saved: dict):
    for name, value in saved.items():
        setattr(orch, name, value)


# ---- /start + /status via fakes (no real Docker) ----

def test_full_activation_flow_success():
    ps_calls = []

    def fake_run_compose(*args, timeout=60):
        import subprocess as sp
        if args[:3] == ("--profile", "openvas", "ps"):
            ps_calls.append(args)
            entries = [{"Service": n, "State": "running", "Health": "healthy"} for n in orch.OPENVAS_SERVICES]
            return sp.CompletedProcess(args, 0, stdout=json.dumps(entries), stderr="")
        if args[:2] == ("exec", "-T"):
            return sp.CompletedProcess(args, 0, stdout="", stderr="")
        raise AssertionError(f"comando compose inesperado: {args}")

    fake_proc = FakeProc(returncode=0)
    written = {}

    saved = _patch_common(["_run_compose", "_spawn_compose_up", "_write_env_vars", "_POLL_INTERVAL_SECONDS"])
    orch._run_compose = fake_run_compose
    orch._spawn_compose_up = lambda: _async_return(fake_proc)
    orch._write_env_vars = lambda values: written.update(values)
    orch._POLL_INTERVAL_SECONDS = 0
    try:
        asyncio.run(orch._run_activation("admin", "s3cr3t", "/run/gvmd/gvmd.sock"))
    finally:
        _restore(saved)

    assert orch._state["provisioned"] is True
    assert orch._state["percent"] == 100
    assert orch._state["error"] is None
    assert orch._state["gvm_user"] == "admin"
    assert orch._state["gvm_password"] == "s3cr3t"
    assert written == {"GVM_SOCKET_PATH": "/run/gvmd/gvmd.sock", "GVM_USER": "admin", "GVM_PASSWORD": "s3cr3t"}

    # Regresion: el `ps` tiene que listar los 16 servicios por nombre --
    # sin esto, Compose puede tomar como objetivo TODO el proyecto (bug
    # real visto en logs de produccion: el propio orquestador se
    # reiniciaba solo en medio de una activacion).
    assert ps_calls, "nunca se llamo a ps"
    assert set(ps_calls[0][6:]) == set(orch.OPENVAS_SERVICES), ps_calls[0]


def test_activation_shows_progress_while_up_still_downloading():
    """Regresion del bug reportado ("se queda en 1% y no avanza"): si
    `up -d` todavia esta bajando imagenes (proceso vivo, sin terminar)
    pero YA hay contenedores que no dependen de una imagen pesada arriba
    y sanos, el porcentaje tiene que reflejarlo en el momento -- nunca
    quedarse pegado en el 1-5% inicial esperando a que el `up -d` entero
    termine."""
    call_count = {"n": 0}

    def fake_run_compose(*args, timeout=60):
        import subprocess as sp
        if args[:3] == ("--profile", "openvas", "ps"):
            call_count["n"] += 1
            # En la primera consulta (up -d todavia "corriendo", ver
            # delay_ticks abajo) ya hay 3 contenedores livianos arriba.
            up_count = 3 if call_count["n"] == 1 else len(orch.OPENVAS_SERVICES)
            entries = [
                {"Service": n, "State": "running", "Health": "healthy"}
                for n in orch.OPENVAS_SERVICES[:up_count]
            ]
            return sp.CompletedProcess(args, 0, stdout=json.dumps(entries), stderr="")
        if args[:2] == ("exec", "-T"):
            return sp.CompletedProcess(args, 0, stdout="", stderr="")
        raise AssertionError(f"comando compose inesperado: {args}")

    # delay_ticks=2: en la primera vuelta del loop, wait_task todavia NO
    # esta resuelto -- exactamente el escenario "up -d sigue bajando
    # imagenes" que congelaba la barra antes de este fix.
    fake_proc = FakeProc(returncode=0, delay_ticks=2)
    percents_seen = []
    orig_sync_percent = orch._sync_percent

    def tracking_sync_percent(done, total):
        pct = orig_sync_percent(done, total)
        percents_seen.append(pct)
        return pct

    saved = _patch_common([
        "_run_compose", "_spawn_compose_up", "_write_env_vars", "_POLL_INTERVAL_SECONDS", "_sync_percent",
    ])
    orch._run_compose = fake_run_compose
    orch._spawn_compose_up = lambda: _async_return(fake_proc)
    orch._write_env_vars = lambda values: None
    orch._POLL_INTERVAL_SECONDS = 0
    orch._sync_percent = tracking_sync_percent
    try:
        asyncio.run(orch._run_activation("admin", "s3cr3t", "/run/gvmd/gvmd.sock"))
    finally:
        _restore(saved)

    assert orch._state["provisioned"] is True
    # La barra tuvo que moverse MAS ALLA del 5% inicial en la primera
    # consulta de ps, con el proceso de `up -d` todavia sin terminar --
    # si este assert fallara, es exactamente el bug original (queda
    # pegado hasta que el `up -d` completo termine).
    assert any(5 < p < 90 for p in percents_seen), percents_seen


def test_activation_flow_fails_fast_if_up_itself_fails():
    """Si `docker compose up -d` termina con codigo de error (imagen
    invalida, permiso denegado al socket, etc.) el fallo se reporta al
    toque -- no hay que esperar 50 minutos de poll para enterarse."""
    def fake_run_compose(*args, timeout=60):
        import subprocess as sp
        if args[:3] == ("--profile", "openvas", "ps"):
            # Un `ps` de mas puede llegar a dispararse antes de que el
            # loop note que `up -d` ya termino (create_task no corre nada
            # hasta el primer punto de espera real) -- no es en si un
            # problema, lo que NO puede pasar es llegar a crear el
            # usuario GVM (`exec`) con `up -d` fallado.
            return sp.CompletedProcess(args, 0, stdout="[]", stderr="")
        raise AssertionError(f"no deberia llegar a `exec` si `up -d` fallo: {args}")

    fake_proc = FakeProc(returncode=1, stdout_data=b"Error: permission denied on /var/run/docker.sock\n")

    saved = _patch_common(["_run_compose", "_spawn_compose_up", "_POLL_INTERVAL_SECONDS"])
    orch._run_compose = fake_run_compose
    orch._spawn_compose_up = lambda: _async_return(fake_proc)
    orch._POLL_INTERVAL_SECONDS = 0
    try:
        asyncio.run(orch._run_activation("admin", "s3cr3t", "/run/gvmd/gvmd.sock"))
    finally:
        _restore(saved)

    assert orch._state["provisioned"] is False
    assert orch._state["running"] is False
    assert "permission denied" in orch._state["error"]


def test_activation_flow_reports_failed_container():
    def fake_run_compose(*args, timeout=60):
        import subprocess as sp
        if args[:3] == ("--profile", "openvas", "ps"):
            entries = [
                {"Service": n, "State": "running", "Health": "healthy"}
                for n in orch.OPENVAS_SERVICES if n != "scap-data"
            ]
            entries.append({"Service": "scap-data", "State": "exited", "ExitCode": 1})
            return sp.CompletedProcess(args, 0, stdout=json.dumps(entries), stderr="")
        raise AssertionError("no deberia llegar a crear el usuario si un contenedor fallo")

    fake_proc = FakeProc(returncode=0)

    saved = _patch_common(["_run_compose", "_spawn_compose_up", "_POLL_INTERVAL_SECONDS"])
    orch._run_compose = fake_run_compose
    orch._spawn_compose_up = lambda: _async_return(fake_proc)
    orch._POLL_INTERVAL_SECONDS = 0
    try:
        asyncio.run(orch._run_activation("admin", "s3cr3t", "/run/gvmd/gvmd.sock"))
    finally:
        _restore(saved)

    assert orch._state["provisioned"] is False
    assert orch._state["running"] is False
    assert "scap-data" in orch._state["error"]


def test_activation_flow_kills_up_process_on_timeout():
    """Si se pasa el deadline generoso (50 min) sin terminar, hay que
    matar el `up -d` de fondo -- si no, quedaria corriendo para siempre
    sin que nadie lo este esperando."""
    def fake_run_compose(*args, timeout=60):
        import subprocess as sp
        # nunca termina de sincronizar -- siempre 0 contenedores listos
        return sp.CompletedProcess(args, 0, stdout="[]", stderr="")

    fake_proc = FakeProc(returncode=0, never_finishes=True)

    saved = _patch_common([
        "_run_compose", "_spawn_compose_up", "_POLL_INTERVAL_SECONDS", "_SYNC_TIMEOUT_SECONDS",
    ])
    orch._run_compose = fake_run_compose
    orch._spawn_compose_up = lambda: _async_return(fake_proc)
    orch._POLL_INTERVAL_SECONDS = 0
    orch._SYNC_TIMEOUT_SECONDS = 0  # el deadline ya esta vencido en la primera vuelta
    try:
        asyncio.run(orch._run_activation("admin", "s3cr3t", "/run/gvmd/gvmd.sock"))
    finally:
        _restore(saved)

    assert orch._state["running"] is False
    assert fake_proc.killed is True
    assert "min" in orch._state["error"]


def test_start_endpoint_rejects_concurrent_activation_and_progress_is_pollable():
    """El lock de /start tiene que evitar que un segundo POST, mientras el
    primero sigue corriendo, dispare una SEGUNDA activacion en paralelo
    (perderia las credenciales/estado de la que ya esta en curso).

    Llama a los handlers de FastAPI (`orch.start` / `orch.get_status`)
    directo, en un solo event loop via asyncio.run, en vez de por HTTP con
    TestClient: probado con TestClient real, la unica forma de dejar la
    "primera" activacion realmente "todavia corriendo" en el momento exacto
    del segundo POST es controlarla con un asyncio.Event, y ese Event
    termina viviendo en el event loop del hilo separado que usa el portal
    de TestClient (BlockingPortal) -- setearlo desde el hilo del test
    (fuera de ese loop) no es thread-safe. Llamando a los handlers directo
    se evita cruzar hilos y el resultado es determinista."""
    calls = []
    proceed = asyncio.Event()

    async def fake_run_activation(gvm_user, gvm_password, gvm_socket_path):
        calls.append((gvm_user, gvm_password))
        await proceed.wait()
        orch._state.update(
            running=False, provisioned=True, error=None, phase="listo", percent=100,
            detail="listo", gvm_user=gvm_user, gvm_password=gvm_password, gvm_socket_path=gvm_socket_path,
        )

    async def scenario():
        r1 = await orch.start({"gvm_user": "admin", "gvm_password": "s3cr3t"})
        assert r1["running"] is True

        # asyncio.create_task() solo programa la tarea de fondo -- no la
        # corre todavia. Un sleep(0) le cede el control al event loop lo
        # justo y necesario para que arranque y quede bloqueada en
        # proceed.wait() (ver fake_run_activation), que es el estado real
        # que se busca reproducir: la primera activacion ya esta EN CURSO
        # cuando llega el segundo POST.
        await asyncio.sleep(0)

        # Todavia esta "corriendo" (bloqueada en proceed.wait(), que recien
        # se libera mas abajo) -- un segundo /start tiene que devolver el
        # estado actual SIN arrancar una segunda activacion en paralelo.
        r2 = await orch.start({"gvm_user": "otro", "gvm_password": "otra"})
        assert r2["running"] is True
        assert len(calls) == 1, "un segundo /start mientras el primero corre no deberia lanzar otra activacion"

        proceed.set()
        for _ in range(50):
            await asyncio.sleep(0)
            if not orch._state["running"]:
                break
        else:
            raise AssertionError("la activacion nunca termino de correr")

        status = await orch.get_status()
        assert status["provisioned"] is True
        # El usuario/password usados son los del PRIMER /start -- el
        # segundo nunca piso el estado de la corrida en curso.
        assert status["gvm_user"] == "admin"
        assert status["gvm_password"] == "s3cr3t"

    saved = _patch_common(["_run_activation"])
    orch._run_activation = fake_run_activation
    try:
        asyncio.run(scenario())
    finally:
        _restore(saved)
