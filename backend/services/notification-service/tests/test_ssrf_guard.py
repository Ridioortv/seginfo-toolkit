"""Test de SSRF en notification-service: antes de este fix, _send_webhook
llamaba con httpx a cualquier 'webhook_url' configurada en un canal
generic_webhook/slack_webhook, sin ninguna validacion -- un admin/
soc_manager del tenant (o una cuenta suya comprometida) podia apuntar un
canal a infraestructura interna (169.254.169.254, localhost, un servicio
de docker-compose, una IP RFC1918) y hacer que notification-service le
pegue por el (SSRF). Ver backend/shared/ssrf_guard.py.

Sin red, sin DB: NotificationChannel se instancia en memoria (nunca se
agrega a una sesion), y las URLs bloqueadas se rechazan ANTES de que
_send_webhook intente abrir cualquier conexion -- si el fix fallara y el
codigo llegara a intentar la llamada HTTP real, este test fallaria por
timeout/error de red en vez de por el mensaje esperado, nunca por un
request exitoso a esas direcciones."""
import asyncio

from app.models import NotificationChannel
from app.services import _send_webhook


def _channel(webhook_url: str, channel_type: str = "generic_webhook") -> NotificationChannel:
    return NotificationChannel(
        id="chan-1",
        organization_id="org-1",
        name="canal de prueba",
        channel_type=channel_type,
        config={"webhook_url": webhook_url},
        enabled=True,
    )


class TestSendWebhookBlocksSsrf:
    def test_rejects_cloud_metadata_url(self):
        channel = _channel("http://169.254.169.254/latest/meta-data/")
        status_, error = asyncio.run(_send_webhook(channel, "s", "b", "high"))
        assert status_ == "failed"
        assert "privada/interna" in error

    def test_rejects_localhost_url(self):
        channel = _channel("http://localhost:6379/")
        status_, error = asyncio.run(_send_webhook(channel, "s", "b", "high"))
        assert status_ == "failed"
        assert "interno bloqueado" in error

    def test_rejects_rfc1918_url(self):
        channel = _channel("http://10.0.0.5:9200/_internal")
        status_, error = asyncio.run(_send_webhook(channel, "s", "b", "high"))
        assert status_ == "failed"
        assert "privada/interna" in error

    def test_rejects_docker_service_name_url(self):
        # No hay red/DNS en el entorno de test -- un nombre de servicio de
        # docker-compose como 'postgres' no resuelve aca, y eso tambien
        # debe terminar en 'failed' (nunca en una excepcion sin manejar
        # que tumbe el request completo).
        channel = _channel("http://postgres:5432/")
        status_, error = asyncio.run(_send_webhook(channel, "s", "b", "high"))
        assert status_ == "failed"

    def test_rejects_non_http_scheme(self):
        channel = _channel("file:///etc/passwd")
        status_, error = asyncio.run(_send_webhook(channel, "s", "b", "high"))
        assert status_ == "failed"
        assert "http" in error
