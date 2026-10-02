"""Test de SSRF en integration-service: antes de este fix, _call_connector
(conectores firewall/edr) y _call_jira (conectores ticketing) llamaban con
httpx a cualquier 'base_url' configurada en un conector, sin ninguna
validacion -- un admin del tenant (o una cuenta de admin comprometida)
podia apuntar un conector a infraestructura interna (169.254.169.254,
localhost, un servicio de docker-compose, una IP RFC1918) y hacer que
integration-service le pegue por el (SSRF). Ver backend/shared/ssrf_guard.py.

Sin red, sin DB: Connector se instancia en memoria (nunca se agrega a una
sesion), y las URLs bloqueadas se rechazan ANTES de que _call_connector/
_call_jira intenten abrir cualquier conexion -- si el fix fallara y el
codigo llegara a intentar la llamada HTTP real, estos tests fallarian por
timeout/error de red en vez de por el mensaje esperado, nunca por un
request exitoso a esas direcciones."""
import asyncio

from app.models import Connector
from app.services import _call_connector, _call_jira


def _connector(config: dict, kind: str = "firewall") -> Connector:
    return Connector(
        id="conn-1",
        organization_id="org-1",
        name="conector de prueba",
        kind=kind,
        config=config,
        enabled=True,
    )


class TestCallConnectorBlocksSsrf:
    def test_rejects_cloud_metadata_url(self):
        connector = _connector({"base_url": "http://169.254.169.254/latest/meta-data/"})
        status_, error = asyncio.run(_call_connector(connector, "block_ip", {"target": "1.2.3.4"}))
        assert status_ == "failed"
        assert "privada/interna" in error

    def test_rejects_localhost_url(self):
        connector = _connector({"base_url": "http://localhost:8000/"})
        status_, error = asyncio.run(_call_connector(connector, "block_ip", {"target": "1.2.3.4"}))
        assert status_ == "failed"
        assert "interno bloqueado" in error

    def test_rejects_rfc1918_url(self):
        connector = _connector({"base_url": "http://172.17.0.5:8080/"})
        status_, error = asyncio.run(_call_connector(connector, "isolate_host", {"target": "host1"}))
        assert status_ == "failed"
        assert "privada/interna" in error

    def test_rejects_docker_service_name_url(self):
        # Sin red/DNS en el entorno de test -- un nombre de servicio de
        # docker-compose como 'auth-service' tampoco resuelve aca, y debe
        # terminar en 'failed' igual (nunca una excepcion sin manejar).
        connector = _connector({"base_url": "http://auth-service:8000/"})
        status_, error = asyncio.run(_call_connector(connector, "block_ip", {"target": "1.2.3.4"}))
        assert status_ == "failed"


class TestCallJiraBlocksSsrf:
    def test_rejects_cloud_metadata_url(self):
        connector = _connector(
            {
                "base_url": "http://169.254.169.254/",
                "email": "bot@example.com",
                "api_token": "token",
                "project_key": "SEC",
            },
            kind="ticketing",
        )
        status_, error, key, url = asyncio.run(_call_jira(connector, "titulo", "desc", "medium"))
        assert status_ == "failed"
        assert "privada/interna" in error
        assert key == "" and url == ""

    def test_rejects_internal_ip_url(self):
        connector = _connector(
            {
                "base_url": "http://10.1.2.3:8080/",
                "email": "bot@example.com",
                "api_token": "token",
                "project_key": "SEC",
            },
            kind="ticketing",
        )
        status_, error, key, url = asyncio.run(_call_jira(connector, "titulo", "desc", "medium"))
        assert status_ == "failed"
        assert "privada/interna" in error
