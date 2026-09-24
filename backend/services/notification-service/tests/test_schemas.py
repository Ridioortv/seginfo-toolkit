"""Tests de los schemas Pydantic de notification-service y del modo
dry-run por defecto (app/services.py::dry_run_enabled). Sin red, sin DB."""
import pytest
from pydantic import ValidationError

from app.schemas import ChannelCreate, NotifyRequest
from app.services import dry_run_enabled


class TestChannelCreateValidation:
    def test_accepts_known_channel_types(self):
        for channel_type in ("email", "slack_webhook", "generic_webhook"):
            channel = ChannelCreate(name="canal", channel_type=channel_type)
            assert channel.channel_type == channel_type

    def test_rejects_unknown_channel_type(self):
        with pytest.raises(ValidationError):
            ChannelCreate(name="canal", channel_type="sms")  # no soportado

    def test_enabled_defaults_to_true(self):
        channel = ChannelCreate(name="canal", channel_type="email")
        assert channel.enabled is True

    def test_config_defaults_to_empty_dict(self):
        channel = ChannelCreate(name="canal", channel_type="email")
        assert channel.config == {}


class TestNotifyRequestDefaults:
    def test_channel_ids_none_means_all_enabled_channels(self):
        req = NotifyRequest(subject="s", body="b")
        assert req.channel_ids is None

    def test_severity_defaults_to_info(self):
        req = NotifyRequest(subject="s", body="b")
        assert req.severity == "info"

    def test_attachments_default_to_none(self):
        req = NotifyRequest(subject="s", body="b")
        assert req.attachments is None


class TestDryRunDefaultsToTrue:
    def test_dry_run_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("NOTIFICATION_DRY_RUN", raising=False)
        assert dry_run_enabled() is True

    def test_dry_run_can_be_disabled_explicitly(self, monkeypatch):
        monkeypatch.setenv("NOTIFICATION_DRY_RUN", "false")
        assert dry_run_enabled() is False
