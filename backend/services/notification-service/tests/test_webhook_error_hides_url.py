import asyncio
import httpx
from app import services
from app.schemas import NotifyLogOut
from datetime import datetime, timezone

SECRET = "https://hooks.slack.com/services/T0/B0/SECRETTOKEN"


class _Channel:
    channel_type = "slack_webhook"
    config = {"webhook_url": SECRET}


def test_failed_webhook_error_has_no_url(monkeypatch):
    monkeypatch.setattr(services, "validate_outbound_url", lambda *a, **k: None)
    real = httpx.AsyncClient

    def fake_client(*a, **k):
        return real(transport=httpx.MockTransport(lambda r: httpx.Response(404)))

    monkeypatch.setattr(services.httpx, "AsyncClient", fake_client)
    status, error = asyncio.run(services._send_webhook(_Channel(), "s", "b", "high"))
    assert status == "failed"
    assert "SECRETTOKEN" not in error and "hooks.slack.com" not in error


def test_log_out_strips_urls_from_old_rows():
    out = NotifyLogOut(
        id="1", channel_id="c", channel_type="slack_webhook", subject="s", status="failed",
        error=f"Client error '404' for url '{SECRET}' For more", created_at=datetime.now(timezone.utc),
    )
    assert "SECRETTOKEN" not in out.error
