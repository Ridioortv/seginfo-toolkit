"""Healthcheck del agente: 'healthy' solo si logro preguntar jobs hace poco; y Falco se corta
al vencer la ventana sin perder lo capturado."""
import os
import sys
import time

import agent


def test_heartbeat_fresh_after_touch(tmp_path, monkeypatch):
    f = tmp_path / "hb"
    monkeypatch.setattr(agent, "HEARTBEAT_FILE", str(f))
    assert agent.heartbeat_is_fresh() is False  # nunca latio -> unhealthy
    agent._touch_heartbeat()
    assert agent.heartbeat_is_fresh() is True


def test_heartbeat_goes_stale(tmp_path, monkeypatch):
    f = tmp_path / "hb"
    monkeypatch.setattr(agent, "HEARTBEAT_FILE", str(f))
    agent._touch_heartbeat()
    old = time.time() - 600
    os.utime(f, (old, old))
    assert agent.heartbeat_is_fresh() is False


def test_run_once_touches_heartbeat_when_poll_works(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "HEARTBEAT_FILE", str(tmp_path / "hb"))
    monkeypatch.setattr(agent, "poll_jobs", lambda: [])
    agent.run_once()
    assert agent.heartbeat_is_fresh() is True


def test_run_once_does_not_touch_heartbeat_when_poll_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "HEARTBEAT_FILE", str(tmp_path / "hb"))

    def boom():
        raise OSError("scan-service caido")

    monkeypatch.setattr(agent, "poll_jobs", boom)
    try:
        agent.run_once()
    except OSError:
        pass
    assert agent.heartbeat_is_fresh() is False


def test_healthcheck_flag_exit_code(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "HEARTBEAT_FILE", str(tmp_path / "hb"))
    monkeypatch.setattr(sys, "argv", ["agent.py", "--healthcheck"])
    try:
        agent.main()
    except SystemExit as exc:
        assert exc.code == 1
    agent._touch_heartbeat()
    try:
        agent.main()
    except SystemExit as exc:
        assert exc.code == 0


def test_fixed_duration_cuts_a_program_that_ignores_its_stop():
    code = "import time; print('{\"rule\":\"R\",\"output\":\"evento\",\"priority\":\"warning\"}', flush=True); time.sleep(120)"
    t0 = time.time()
    rc, out, err, stopped = agent._run_for_fixed_duration([sys.executable, "-c", code], 1, grace_seconds=5)
    assert stopped is True and b"evento" in out
    assert time.time() - t0 < 15


def test_run_falco_keeps_events_when_it_has_to_stop_it(monkeypatch):
    line = '{"rule":"Terminal shell in container","output":"x","priority":"Warning"}\n'
    monkeypatch.setattr(agent, "_run_for_fixed_duration", lambda cmd, secs, grace_seconds=10: (-15, line.encode(), b"", True))
    raw, findings, error = agent.run_falco("host", {"duration_minutes": 1})
    assert error == "" and len(findings) == 1
