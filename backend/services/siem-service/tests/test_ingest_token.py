"""POST /logs/ingest: con SIEM_INGEST_TOKEN definido exige X-Ingest-Token."""
from backend.shared.ingest_auth import ingest_headers, ingest_token_valid


def test_no_token_configured_allows_everything(monkeypatch):
    monkeypatch.delenv("SIEM_INGEST_TOKEN", raising=False)
    assert ingest_token_valid(None) is True
    assert ingest_headers() == {}


def test_token_configured_requires_exact_match(monkeypatch):
    monkeypatch.setenv("SIEM_INGEST_TOKEN", "s3cr3t")
    assert ingest_token_valid(None) is False
    assert ingest_token_valid("otro") is False
    assert ingest_token_valid("s3cr3t") is True
    assert ingest_headers() == {"X-Ingest-Token": "s3cr3t"}


def test_endpoint_rejects_missing_token(monkeypatch):
    from fastapi.testclient import TestClient
    import app.main as m

    monkeypatch.setenv("SIEM_INGEST_TOKEN", "s3cr3t")
    r = TestClient(m.app).post("/logs/ingest", json={"events": []})
    assert r.status_code == 401


def test_unset_token_fails_closed_outside_development(monkeypatch):
    monkeypatch.delenv("SIEM_INGEST_TOKEN", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert ingest_token_valid(None) is False


def test_placeholder_token_rejected_outside_development(monkeypatch):
    monkeypatch.setenv("SIEM_INGEST_TOKEN", "changeme-ingest-token")
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert ingest_token_valid("changeme-ingest-token") is False


def test_org_token_is_bound_to_its_organization(monkeypatch):
    from backend.shared.ingest_auth import org_ingest_token

    monkeypatch.setenv("SIEM_INGEST_TOKEN", "master-token-master-token")
    tok_a = org_ingest_token("org-a")
    assert ingest_token_valid(tok_a, "org-a") is True
    assert ingest_token_valid(tok_a, "org-b") is False  # el token de A no escribe en B
    assert ingest_token_valid(tok_a, None) is False
    assert ingest_token_valid("master-token-master-token", "org-b") is True  # servicios internos
