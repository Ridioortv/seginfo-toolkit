"""Login: solo cuentan los intentos FALLIDOS. Acertar la contrasena despues de
varios errores entra (antes daba 429), un login correcto borra los fallos, y la
fuerza bruta sigue frenada (N fallos seguidos bloquean la ventana)."""
import asyncio
import types

import pytest
from fastapi import HTTPException

import app.main as m
from backend.shared import rate_limit


class _Db:
    async def commit(self):
        pass


class _Req:
    client = types.SimpleNamespace(host="203.0.113.7")


def _setup(monkeypatch, correct="buena-clave-123"):
    # sin Redis: usa el contador en memoria
    class Down:
        async def get(self, *a, **k):
            raise ConnectionError()
        incr = delete = expire = get

    monkeypatch.setattr(rate_limit, "_get_redis", lambda: Down())
    rate_limit._fail_memory.clear()

    async def authenticate(db, email, password, totp=None):
        if password != correct:
            return None
        return types.SimpleNamespace(
            organization_id=None, role=types.SimpleNamespace(name="admin"), id="u1", email=email,
        )

    async def audit(*a, **k):
        pass

    monkeypatch.setattr(m.services, "authenticate", authenticate)
    monkeypatch.setattr(m.services, "record_audit_event", audit)
    monkeypatch.setattr(m.services, "issue_tokens", lambda user, role: ("acc", "ref"))


def _login(email, password):
    payload = types.SimpleNamespace(email=email, password=password, totp_code=None)
    return asyncio.run(m.login(payload, _Req(), _Db()))


def test_correct_password_enters_after_several_wrong_ones(monkeypatch):
    _setup(monkeypatch)
    for _ in range(8):
        with pytest.raises(HTTPException) as e:
            _login("a@b.com", "mala")
        assert e.value.status_code == 401
    assert _login("a@b.com", "buena-clave-123").access_token == "acc"


def test_successful_logins_do_not_consume_the_quota(monkeypatch):
    _setup(monkeypatch)
    for _ in range(40):  # mas que el tope por IP (20) y por email (10)
        assert _login("a@b.com", "buena-clave-123").access_token == "acc"


def test_success_clears_previous_failures(monkeypatch):
    _setup(monkeypatch)
    for _ in range(9):
        with pytest.raises(HTTPException):
            _login("a@b.com", "mala")
    _login("a@b.com", "buena-clave-123")
    for _ in range(9):  # vuelve a tener los 10 intentos completos
        with pytest.raises(HTTPException) as e:
            _login("a@b.com", "mala")
        assert e.value.status_code == 401


def test_brute_force_still_blocked(monkeypatch):
    _setup(monkeypatch)
    for _ in range(10):
        with pytest.raises(HTTPException) as e:
            _login("a@b.com", "mala")
        assert e.value.status_code == 401
    with pytest.raises(HTTPException) as e:
        _login("a@b.com", "buena-clave-123")
    assert e.value.status_code == 429
