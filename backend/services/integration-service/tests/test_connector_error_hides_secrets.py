import asyncio
import httpx
from app import services
from app.schemas import ActionLogOut
from datetime import datetime, timezone


class _Connector:
    kind = "firewall"
    config = {"base_url": "https://fw.example/api", "header_name": "X-Api-Key", "api_key": "enc"}


def test_failed_connector_error_has_no_url_or_key(monkeypatch):
    monkeypatch.setattr(services, "validate_outbound_url", lambda *a, **k: None)
    monkeypatch.setattr(services, "decrypt_secret", lambda v: "SUPERSECRETKEY")
    real = httpx.AsyncClient
    monkeypatch.setattr(
        services.httpx, "AsyncClient",
        lambda *a, **k: real(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
    )
    status, error = asyncio.run(services._call_connector(_Connector(), "block_ip", {"target": "1.2.3.4"}))
    assert status == "failed" and "SUPERSECRETKEY" not in error and "fw.example" not in error


def test_log_out_strips_urls():
    out = ActionLogOut(id="1", connector_id="c", action="a", target="t", status="failed",
                       error="Server error for url 'https://fw.example/api/x?k=1'", created_at=datetime.now(timezone.utc))
    assert "fw.example" not in out.error
