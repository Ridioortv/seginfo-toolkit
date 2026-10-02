"""Tests de la logica pura de app/services.py -- sin DB, sin red, sin TLS
real (fetch_crtsh_subdomains, fetch_tls_certificate y run_domain_check, que
si hacen I/O, quedan fuera de este archivo a proposito)."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services import (
    cert_alert_for_expiry,
    diff_new_hostnames,
    is_blocked_target_ip,
    normalize_domain,
    parse_crtsh_entries,
    should_create_alert,
)


class TestNormalizeDomain:
    def test_plain_domain_is_unchanged(self):
        assert normalize_domain("empresa.com") == "empresa.com"

    def test_strips_protocol(self):
        assert normalize_domain("https://empresa.com") == "empresa.com"
        assert normalize_domain("http://empresa.com") == "empresa.com"

    def test_strips_trailing_path(self):
        assert normalize_domain("empresa.com/login?x=1") == "empresa.com"
        assert normalize_domain("https://empresa.com/algun/path") == "empresa.com"

    def test_lowercases(self):
        assert normalize_domain("EMPRESA.COM") == "empresa.com"

    def test_rejects_domain_without_dot(self):
        with pytest.raises(ValueError):
            normalize_domain("localhost")

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError):
            normalize_domain("")

    def test_rejects_loopback_ip_literal(self):
        with pytest.raises(ValueError):
            normalize_domain("127.0.0.1")

    def test_rejects_cloud_metadata_ip_literal(self):
        # 169.254.169.254 -- endpoint de metadata de AWS/GCP/Azure. Si un
        # cliente pudiera registrar esto como "dominio a monitorear", el
        # scheduler de este servicio terminaria conectandose a su propio
        # endpoint de metadata interno (SSRF) cada ASM_CHECK_INTERVAL_HOURS.
        with pytest.raises(ValueError):
            normalize_domain("169.254.169.254")

    def test_rejects_private_rfc1918_ip_literal(self):
        with pytest.raises(ValueError):
            normalize_domain("10.0.0.5")
        with pytest.raises(ValueError):
            normalize_domain("192.168.1.1")

    def test_allows_public_ip_literal(self):
        # Una IP publica literal no es un vector de SSRF contra
        # infraestructura interna -- no hace falta bloquearla.
        assert normalize_domain("8.8.8.8") == "8.8.8.8"

    def test_normal_domain_name_is_unaffected_by_ip_check(self):
        assert normalize_domain("empresa.com") == "empresa.com"


class TestParseCrtshEntries:
    def test_multiple_sans_in_one_name_value(self):
        entries = [{"name_value": "empresa.com\nwww.empresa.com\nmail.empresa.com"}]
        assert parse_crtsh_entries(entries) == {"empresa.com", "www.empresa.com", "mail.empresa.com"}

    def test_wildcard_is_normalized_to_base_domain(self):
        entries = [{"name_value": "*.empresa.com"}]
        assert parse_crtsh_entries(entries) == {"empresa.com"}

    def test_empty_list_returns_empty_set(self):
        assert parse_crtsh_entries([]) == set()

    def test_mixed_entries_deduplicate_across_certificates(self):
        entries = [
            {"name_value": "empresa.com\n*.empresa.com"},
            {"name_value": "www.empresa.com"},
        ]
        assert parse_crtsh_entries(entries) == {"empresa.com", "www.empresa.com"}


class TestDiffNewHostnames:
    def test_returns_only_hostnames_not_already_known(self):
        known = {"empresa.com", "www.empresa.com"}
        discovered = {"empresa.com", "www.empresa.com", "mail.empresa.com"}
        assert diff_new_hostnames(known, discovered) == {"mail.empresa.com"}

    def test_no_new_hostnames_returns_empty_set(self):
        known = {"empresa.com"}
        assert diff_new_hostnames(known, {"empresa.com"}) == set()


class TestCertAlertForExpiry:
    def _now(self):
        return datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_already_expired_is_critical(self):
        now = self._now()
        not_after = now - timedelta(days=1)
        assert cert_alert_for_expiry(not_after, now) == ("cert_expired", "critical")

    def test_expiring_in_5_days_is_high(self):
        now = self._now()
        not_after = now + timedelta(days=5)
        assert cert_alert_for_expiry(not_after, now) == ("cert_expiring", "high")

    def test_expiring_in_25_days_is_medium(self):
        now = self._now()
        not_after = now + timedelta(days=25)
        assert cert_alert_for_expiry(not_after, now) == ("cert_expiring", "medium")

    def test_expiring_in_60_days_is_none(self):
        now = self._now()
        not_after = now + timedelta(days=60)
        assert cert_alert_for_expiry(not_after, now) is None

    def test_exactly_7_days_is_high(self):
        now = self._now()
        not_after = now + timedelta(days=7)
        assert cert_alert_for_expiry(not_after, now) == ("cert_expiring", "high")

    def test_exactly_30_days_is_medium(self):
        now = self._now()
        not_after = now + timedelta(days=30)
        assert cert_alert_for_expiry(not_after, now) == ("cert_expiring", "medium")

    def test_just_over_30_days_is_none(self):
        now = self._now()
        not_after = now + timedelta(days=30, seconds=1)
        assert cert_alert_for_expiry(not_after, now) is None


class TestShouldCreateAlert:
    def test_no_existing_alerts_creates_new_one(self):
        assert should_create_alert([], "new_subdomain") is True

    def test_recent_unacknowledged_alert_of_same_type_blocks_new_one(self):
        recent = SimpleNamespace(
            alert_type="new_subdomain", created_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        assert should_create_alert([recent], "new_subdomain") is False

    def test_old_alert_outside_cooldown_allows_new_one(self):
        old = SimpleNamespace(
            alert_type="new_subdomain", created_at=datetime.now(timezone.utc) - timedelta(hours=48)
        )
        assert should_create_alert([old], "new_subdomain", cooldown_hours=24) is True

    def test_alert_of_a_different_type_does_not_block(self):
        recent_other_type = SimpleNamespace(
            alert_type="cert_expiring", created_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        assert should_create_alert([recent_other_type], "new_subdomain") is True


class TestIsBlockedTargetIp:
    def test_loopback_v4_is_blocked(self):
        assert is_blocked_target_ip("127.0.0.1") is True

    def test_loopback_v6_is_blocked(self):
        assert is_blocked_target_ip("::1") is True

    def test_cloud_metadata_ip_is_blocked(self):
        assert is_blocked_target_ip("169.254.169.254") is True

    def test_rfc1918_private_ranges_are_blocked(self):
        assert is_blocked_target_ip("10.1.2.3") is True
        assert is_blocked_target_ip("172.16.0.1") is True
        assert is_blocked_target_ip("192.168.0.1") is True

    def test_unspecified_is_blocked(self):
        assert is_blocked_target_ip("0.0.0.0") is True

    def test_multicast_is_blocked(self):
        assert is_blocked_target_ip("224.0.0.1") is True

    def test_public_ip_is_not_blocked(self):
        assert is_blocked_target_ip("8.8.8.8") is False
        assert is_blocked_target_ip("1.1.1.1") is False

    def test_invalid_ip_string_is_not_blocked(self):
        # No es este chequeo el que valida formato de IP -- un hostname
        # normal (no una IP) devuelve False aca, no una excepcion.
        assert is_blocked_target_ip("not-an-ip") is False
        assert is_blocked_target_ip("empresa.com") is False
