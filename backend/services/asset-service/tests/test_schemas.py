"""Tests de los schemas Pydantic de asset-service: valores por defecto y
que un enum invalido (environment/criticality) se rechace en la validacion,
antes de llegar a la base. Sin DB, sin red -- valida el contrato de la API."""
import pytest
from pydantic import ValidationError

from app.schemas import AssetCreate, AssetUpdate
from app.models import AssetCriticality, AssetEnvironment


class TestAssetCreateDefaults:
    def test_defaults_to_production_and_medium_criticality(self):
        asset = AssetCreate(hostname="web-01")
        assert asset.environment == AssetEnvironment.production
        assert asset.criticality == AssetCriticality.medium
        assert asset.tags == []

    def test_only_hostname_or_ip_is_needed(self):
        assert AssetCreate(hostname="web-01").ip_address == ""
        assert AssetCreate(ip_address="10.0.0.5").hostname == ""

    def test_empty_asset_is_rejected(self):
        # la pantalla ya lo frenaba; la API aceptaba el POST directo
        for kwargs in ({}, {"hostname": ""}, {"hostname": "   ", "ip_address": " "}):
            with pytest.raises(ValidationError):
                AssetCreate(**kwargs)

    def test_whitespace_is_trimmed(self):
        assert AssetCreate(hostname="  web-01 ").hostname == "web-01"


class TestAssetCreateValidation:
    def test_rejects_unknown_environment(self):
        with pytest.raises(ValidationError):
            AssetCreate(hostname="web-01", environment="produccion-mal-escrito")

    def test_rejects_unknown_criticality(self):
        with pytest.raises(ValidationError):
            AssetCreate(hostname="web-01", criticality="urgente")

    def test_accepts_valid_enum_values(self):
        asset = AssetCreate(hostname="web-01", environment="staging", criticality="high")
        assert asset.environment == AssetEnvironment.staging
        assert asset.criticality == AssetCriticality.high


class TestAssetUpdatePartial:
    def test_all_fields_default_to_none_for_partial_update(self):
        update = AssetUpdate()
        assert update.hostname is None
        assert update.is_active is None

    def test_rejects_unknown_criticality_on_update_too(self):
        with pytest.raises(ValidationError):
            AssetUpdate(criticality="no-existe")


class TestIpValidation:
    """La IP se usa luego como objetivo de escaneo: la API aceptaba "999.1.1.1"."""

    @pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.0", "abc", "10.0.0.1; ls", "1.2.3.4/24", "http://x"])
    def test_invalid_ip_is_rejected_on_create(self, bad):
        with pytest.raises(ValidationError):
            AssetCreate(hostname="web-01", ip_address=bad)

    def test_invalid_ip_is_rejected_on_update(self):
        with pytest.raises(ValidationError):
            AssetUpdate(ip_address="999.1.1.1")

    def test_valid_ipv4_ipv6_and_blank_are_accepted(self):
        assert AssetCreate(hostname="a", ip_address=" 10.0.0.5 ").ip_address == "10.0.0.5"
        assert AssetCreate(hostname="a", ip_address="::1").ip_address == "::1"
        assert AssetCreate(hostname="a", ip_address="").ip_address == ""
        assert AssetUpdate(ip_address="").ip_address == ""
        assert AssetUpdate().ip_address is None
