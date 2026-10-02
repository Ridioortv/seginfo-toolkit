"""Tests de seguridad para app/services.py::create_group.

Bug real encontrado: POST /asset-groups guardaba payload.asset_ids (lo que
manda el cliente) tal cual, sin chequear que esos activos pertenezcan a la
organizacion de quien esta pidiendo el grupo. Un admin/soc_manager de la
organizacion A podia crear un AssetGroup que listara ids de activos de la
organizacion B (adivinados, filtrados de otro lado, etc.) -- GET
/asset-groups despues devolvia esos ids ajenos tal cual. get_assets_by_ids
ya existia (filtra por organization_id, ver su docstring) pero nunca se
llamaba desde create_group.

Sin DB real: se monkeypatchea get_assets_by_ids (la unica funcion de este
modulo que create_group usa para tocar la base aparte de add/flush/refresh,
que se fake-an con no-ops) -- mismo espiritu que los demas tests de este
paquete (logica pura/aislada, sin Postgres)."""
import asyncio
from types import SimpleNamespace

from app import services
from app.schemas import AssetGroupCreate


class _FakeDb:
    def add(self, obj):
        pass

    async def flush(self):
        return None

    async def refresh(self, obj):
        return None


class TestCreateGroupOnlyKeepsAssetsFromTheCallerOrganization:
    def test_foreign_organization_asset_ids_are_dropped(self, monkeypatch):
        # El payload pide 3 activos: dos son de la organizacion del
        # caller, uno es de otra organizacion (o no existe). Solo los dos
        # propios deben terminar en el grupo.
        owned_asset_ids = {"asset-own-1", "asset-own-2"}

        async def fake_get_assets_by_ids(db, asset_ids, organization_id):
            assert organization_id == "org-caller"
            return [SimpleNamespace(id=aid) for aid in asset_ids if aid in owned_asset_ids]

        monkeypatch.setattr(services, "get_assets_by_ids", fake_get_assets_by_ids)

        payload = AssetGroupCreate(
            name="Grupo mixto",
            asset_ids=["asset-own-1", "asset-own-2", "asset-de-otra-org"],
        )
        group = asyncio.run(services.create_group(_FakeDb(), payload, "org-caller"))

        assert set(group.asset_ids) == owned_asset_ids
        assert "asset-de-otra-org" not in group.asset_ids

    def test_group_with_only_foreign_ids_ends_up_empty(self, monkeypatch):
        async def fake_get_assets_by_ids(db, asset_ids, organization_id):
            return []

        monkeypatch.setattr(services, "get_assets_by_ids", fake_get_assets_by_ids)

        payload = AssetGroupCreate(name="Grupo vacio", asset_ids=["asset-ajeno-1", "asset-ajeno-2"])
        group = asyncio.run(services.create_group(_FakeDb(), payload, "org-caller"))

        assert group.asset_ids == []

    def test_group_with_no_asset_ids_is_unaffected(self, monkeypatch):
        called = {"count": 0}

        async def fake_get_assets_by_ids(db, asset_ids, organization_id):
            called["count"] += 1
            assert asset_ids == []
            return []

        monkeypatch.setattr(services, "get_assets_by_ids", fake_get_assets_by_ids)

        payload = AssetGroupCreate(name="Grupo sin activos todavia")
        group = asyncio.run(services.create_group(_FakeDb(), payload, "org-caller"))

        assert group.asset_ids == []
        assert called["count"] == 1
