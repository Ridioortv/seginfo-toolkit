"""build_client: con OPENSEARCH_ADMIN_PASSWORD usa usuario/contrasena; sin ella, no."""
from app import opensearch_client


def test_client_uses_basic_auth_when_password_set(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr(opensearch_client, "AsyncOpenSearch", Fake)
    monkeypatch.setenv("OPENSEARCH_ADMIN_PASSWORD", "Os!abc123XYZ9X")
    monkeypatch.setenv("OPENSEARCH_USE_SSL", "true")
    monkeypatch.delenv("OPENSEARCH_USER", raising=False)
    opensearch_client.build_client()
    assert seen["http_auth"] == ("admin", "Os!abc123XYZ9X")
    assert seen["use_ssl"] is True


def test_client_without_password_has_no_auth(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr(opensearch_client, "AsyncOpenSearch", Fake)
    monkeypatch.delenv("OPENSEARCH_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OPENSEARCH_PASSWORD", raising=False)
    opensearch_client.build_client()
    assert seen["http_auth"] is None
