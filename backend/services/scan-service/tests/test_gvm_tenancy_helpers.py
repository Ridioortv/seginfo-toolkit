"""Tests de la logica REAL (sin mocks, sin DB) que decide el aislamiento
multi-tenant de recursos GVM -- ver app/models.py::GvmOwnedResource y el
docstring de app/services.py::_resolve_owner/_filter_by_org para el por
que de esto: gvmd/ospd-openvas no tienen ningun concepto de organizacion,
asi que antes de este fix cualquier usuario autenticado de CUALQUIER
organizacion podia listar/leer/borrar las credenciales y targets GVM de
TODAS las demas organizaciones del mismo deployment.

Las funciones publicas async (resolve_gvm_resource_org,
filter_gvm_resources_by_org, resolve_gvm_task_org) solo le agregan a estas
el fetch desde la DB -- se prueban a nivel HTTP con mocks en
test_openvas_dashboard_endpoints.py."""
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.services import _filter_by_org, _resolve_owner


class TestResolveOwner:
    def test_known_owner_wins(self):
        assert _resolve_owner({"cred1": "org-a", "cred2": "org-b"}, "cred1") == "org-a"

    def test_unknown_id_falls_back_to_default_org(self):
        # Backfill: un recurso creado antes de este fix (o a mano con
        # gvm-cli/gvm-tools, por fuera de la UI) no tiene fila de
        # ownership -- cae a DEFAULT_ORGANIZATION_ID, igual que el resto
        # del servicio hace para columnas organization_id nuevas.
        assert _resolve_owner({}, "cred-viejo") == DEFAULT_ORGANIZATION_ID


class TestFilterByOrg:
    def test_keeps_only_items_owned_by_the_caller_org(self):
        owners = {"cred-a": "org-a", "cred-b": "org-b"}
        items = [{"id": "cred-a", "name": "x"}, {"id": "cred-b", "name": "y"}]
        assert _filter_by_org(owners, items, "org-a") == [{"id": "cred-a", "name": "x"}]

    def test_cross_tenant_leak_is_blocked(self):
        # El caso real que motivo el fix: org-a NO debe ver un recurso de
        # org-b, incluso aunque gvmd (que no sabe nada de organizaciones)
        # lo haya devuelto en la misma lista.
        owners = {"cred-b": "org-b"}
        items = [{"id": "cred-b", "name": "credencial de otra empresa"}]
        assert _filter_by_org(owners, items, "org-a") == []

    def test_unowned_legacy_item_only_visible_to_default_org(self):
        items = [{"id": "legacy-cred", "name": "z"}]
        assert _filter_by_org({}, items, DEFAULT_ORGANIZATION_ID) == items
        assert _filter_by_org({}, items, "org-a") == []
