"""Tests de integration-service: cifrado/ocultamiento de credenciales de
conectores (api_key/api_token) y el modo dry-run por defecto. Son las dos
garantias de seguridad mas importantes de este servicio: un secreto nunca
se devuelve en texto plano por la API, y ninguna accion real ocurre sin que
un operador la habilite explicitamente."""
from app.services import (
    _encrypt_secret_fields,
    _decrypt_secret_fields,
    redact_connector_config,
    dry_run_enabled,
)


class TestSecretFieldsRoundtrip:
    def test_encrypt_then_decrypt_recovers_original(self):
        config = {"base_url": "https://firewall.example.com", "api_key": "s3cr3t-token"}
        encrypted = _encrypt_secret_fields(config)
        assert encrypted["api_key"] != "s3cr3t-token"
        assert encrypted["base_url"] == config["base_url"]  # campos no-secretos, intactos

        decrypted = _decrypt_secret_fields(encrypted)
        assert decrypted["api_key"] == "s3cr3t-token"

    def test_fields_without_secrets_are_untouched(self):
        config = {"base_url": "https://x.example.com", "headers": {"X-Custom": "1"}}
        assert _encrypt_secret_fields(config) == config

    def test_empty_secret_value_is_not_encrypted(self):
        config = {"api_key": ""}
        assert _encrypt_secret_fields(config)["api_key"] == ""


class TestRedactConnectorConfig:
    def test_never_leaks_secret_value(self):
        config = {"base_url": "https://x.example.com", "api_key": "encrypted-blob-xyz", "api_token": "otro-secreto"}
        redacted = redact_connector_config(config)
        assert redacted["api_key"] == "•" * 8
        assert redacted["api_token"] == "•" * 8
        assert "encrypted-blob-xyz" not in str(redacted)
        assert "otro-secreto" not in str(redacted)

    def test_non_secret_fields_pass_through(self):
        config = {"base_url": "https://x.example.com"}
        assert redact_connector_config(config) == config


class TestDryRunDefaultsToTrue:
    def test_dry_run_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("INTEGRATION_DRY_RUN", raising=False)
        assert dry_run_enabled() is True

    def test_dry_run_can_be_disabled_explicitly(self, monkeypatch):
        monkeypatch.setenv("INTEGRATION_DRY_RUN", "false")
        assert dry_run_enabled() is False
