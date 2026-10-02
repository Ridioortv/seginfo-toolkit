"""Tests para app/services.py::_notify_soar y su uso en ingest_events.

Bug real corregido: _notify_soar ya devolvia una senal de exito/fracaso
(ahora explicita como bool) pero el caller en ingest_events descartaba el
resultado (`await _notify_soar(...)` sin usarlo), asi que Alert.soar_triggered
quedaba siempre en el default False de la columna (ver app/models.py)
sin importar si soar-service de verdad recibio el trigger -- el dashboard
de alertas nunca podia mostrar que una alerta SI disparo una respuesta
automatica.

Se mockea httpx.AsyncClient (sin red real) para poder testear las dos
ramas (soar-service responde 2xx / no responde o devuelve error) igual que
hace el resto del proyecto con I/O externo; no se necesita DB real porque
_notify_soar solo lee atributos del objeto `alert` que se le pasa."""
import types

import httpx
import pytest

from app import services


class _FakeResponse:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=self)


class _FakeAsyncClient:
    """Reemplaza httpx.AsyncClient dentro de app.services para no pegarle a
    la red real. `responder` decide que pasa en el POST a /trigger."""

    def __init__(self, responder):
        self._responder = responder

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def post(self, url, json=None, headers=None):
        self.last_headers = headers
        return self._responder(url, json)


def _make_alert(alert_id="alert-1", rule_name="Regla X", severity="high", matched_event=None):
    return types.SimpleNamespace(
        id=alert_id,
        rule_name=rule_name,
        severity=types.SimpleNamespace(value=severity),
        matched_event=matched_event or {},
    )


class TestNotifySoarReturnValue:
    @pytest.mark.asyncio
    async def test_returns_true_when_soar_service_accepts_the_trigger(self, monkeypatch):
        fake_client = _FakeAsyncClient(lambda url, json: _FakeResponse(200))
        monkeypatch.setattr(services.httpx, "AsyncClient", fake_client)
        ok = await services._notify_soar(_make_alert(), "org-1")
        assert ok is True

    @pytest.mark.asyncio
    async def test_sends_a_service_jwt_with_the_trigger_so_soar_service_can_authenticate_it(self, monkeypatch):
        # Regresion: soar-service's POST /trigger now requires a JWT (ver
        # soar-service/app/main.py::trigger) -- antes _notify_soar no
        # mandaba ninguna credencial, lo que permitia a cualquiera que
        # alcanzara el puerto publicado de soar-service disparar los
        # playbooks de otra organizacion sin autenticarse.
        fake_client = _FakeAsyncClient(lambda url, json: _FakeResponse(200))
        monkeypatch.setattr(services.httpx, "AsyncClient", fake_client)
        ok = await services._notify_soar(_make_alert(), "org-1")
        assert ok is True
        assert fake_client.last_headers is not None
        assert fake_client.last_headers["Authorization"].startswith("Bearer ")

    @pytest.mark.asyncio
    async def test_returns_false_when_soar_service_errors(self, monkeypatch):
        monkeypatch.setattr(
            services.httpx, "AsyncClient", _FakeAsyncClient(lambda url, json: _FakeResponse(500))
        )
        ok = await services._notify_soar(_make_alert(), "org-1")
        assert ok is False

    @pytest.mark.asyncio
    async def test_returns_false_when_soar_service_is_unreachable(self, monkeypatch):
        def _raise(url, json):
            raise httpx.ConnectError("no se pudo conectar")

        monkeypatch.setattr(services.httpx, "AsyncClient", _FakeAsyncClient(_raise))
        ok = await services._notify_soar(_make_alert(), "org-1")
        assert ok is False
