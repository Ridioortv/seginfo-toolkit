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

    def test_all_fields_are_optional(self):
        # un activo minimo (sin ningun campo) sigue siendo valido -- el
        # inventario se puede completar despues.
        asset = AssetCreate()
        assert asset.hostname == ""


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
