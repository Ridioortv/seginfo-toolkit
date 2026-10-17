import pytest
from app.services import repo_url_safety_error


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:1/x.git",
    "https://169.254.169.254/latest/x",
    "https://10.0.0.5/org/repo.git",
    "https://100.100.100.200/x.git",
    "https://localhost/x.git",
])
def test_internal_hosts_rejected(url, monkeypatch):
    monkeypatch.delenv("CODEREPO_ALLOW_PRIVATE_NETWORK", raising=False)
    assert repo_url_safety_error(url)


def test_private_allowed_only_with_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("CODEREPO_ALLOW_PRIVATE_NETWORK", "true")
    assert repo_url_safety_error("https://10.0.0.5/org/repo.git") is None
