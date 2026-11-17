"""Canal de Microsoft Teams: tarjeta adaptable, mismo cuidado con SSRF y sin filtrar la URL del webhook."""
import asyncio
import json

import httpx

from app import services
from app.schemas import ChannelCreate

SECRET = "https://prod-12.westus.logic.azure.com/workflows/SECRETTOKEN/triggers/manual"


class _Channel:
    channel_type = "teams_webhook"
    config = {"webhook_url": SECRET}


def test_channel_type_is_accepted():
    assert ChannelCreate(name="Teams SOC", channel_type="teams_webhook", config={"webhook_url": SECRET}).channel_type == "teams_webhook"


def test_teams_payload_is_an_adaptive_card_with_severity_and_text():
    p = services.teams_payload("Ticket SEC-1 creado", "Panel expuesto", "critical")
    card = p["attachments"][0]["content"]
    assert p["type"] == "message" and card["type"] == "AdaptiveCard"
    assert card["body"][0]["text"] == "[CRITICAL] Ticket SEC-1 creado" and card["body"][1]["text"] == "Panel expuesto"
    assert card["body"][0]["color"] == "Attention"
    assert services.teams_payload("s", "b", "raro")["attachments"][0]["content"]["body"][0]["color"] == "Default"
    assert len(services.teams_payload("x" * 1000, "y" * 9000, "low")["attachments"][0]["content"]["body"][1]["text"]) == 3000


def test_teams_send_posts_card_and_never_leaks_url(monkeypatch):
    sent = {}
    monkeypatch.setattr(services, "validate_outbound_url", lambda *a, **k: None)
    real = httpx.AsyncClient

    def fake_client(*a, **k):
        def handler(r):
            sent["body"] = json.loads(r.content)
            return httpx.Response(202)
        return real(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(services.httpx, "AsyncClient", fake_client)
    assert asyncio.run(services._send_webhook(_Channel(), "Titulo", "Cuerpo", "high")) == ("sent", "")
    assert sent["body"]["attachments"][0]["content"]["body"][0]["text"] == "[HIGH] Titulo"

    def failing(*a, **k):
        return real(transport=httpx.MockTransport(lambda r: httpx.Response(400)))

    monkeypatch.setattr(services.httpx, "AsyncClient", failing)
    status, error = asyncio.run(services._send_webhook(_Channel(), "s", "b", "high"))
    assert status == "failed" and "SECRETTOKEN" not in error and "logic.azure" not in error
