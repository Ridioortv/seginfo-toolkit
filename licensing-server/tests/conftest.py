import pytest


@pytest.fixture(autouse=True)
def _fresh_paypal_token_cache():
    """El token de PayPal se cachea unos minutos en memoria: cada test arranca sin ese cache."""
    from app import paypal

    paypal._token_cache.clear()
    yield
    paypal._token_cache.clear()
