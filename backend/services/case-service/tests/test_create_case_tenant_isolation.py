"""Tests de seguridad para POST /cases (app/main.py::create_case).

Bug real encontrado: el endpoint no exigia JWT y confiaba en un
organization_id que mandaba el propio caller en el body -- /api/cases se
expone externamente por el ingress sin distincion de metodo (ver
infra/k8s/base/ingress.yaml), asi que cualquiera en internet, sin ninguna
credencial, podia inyectar casos falsos en la cola de SOC de CUALQUIER
organizacion con solo adivinar/enumerar un organization_id ajeno.

Sin DB, sin red: se llama a la coroutine del endpoint directamente (bypass
de la inyeccion de dependencies de FastAPI, que solo ocurre dentro de un
ASGI app real) con un `claims` armado a mano y servicios internos
monkeypatcheados -- mismo espiritu que los demas tests de este paquete
(logica pura, sin Postgres)."""
import asyncio
import inspect

import pytest
from pydantic import ValidationError

from app import main
from app.schemas import CaseCreate


class TestCaseCreateSchemaDropsClientOrganizationId:
    def test_organization_id_is_no_longer_a_field(self):
        # Un atacante mandando organization_id en el body no debe poder
        # hacer que el modelo lo conserve de ninguna forma.
        payload = CaseCreate(title="Caso", organization_id="org-de-otra-empresa")
        assert not hasattr(payload, "organization_id")
        assert "organization_id" not in payload.model_dump()


class TestCaseCreateEndpointRequiresAuthAndIgnoresClientOrgId:
    def test_signature_requires_claims_dependency(self):
        # El endpoint tiene que depender de get_current_claims -- sin eso,
        # FastAPI lo deja accesible sin ningun token (el bug original).
        sig = inspect.signature(main.create_case)
        assert "claims" in sig.parameters

    def test_organization_id_always_comes_from_claims_not_payload(self, monkeypatch):
        captured = {}

        async def fake_create_case(db, payload, organization_id, actor=""):
            captured["organization_id"] = organization_id
            captured["actor"] = actor
            return object()

        async def fake_commit():
            return None

        monkeypatch.setattr(main.services, "create_case", fake_create_case)
        monkeypatch.setattr(main.cases_created_total.labels(priority="medium", source="manual"), "inc", lambda: None)

        payload = CaseCreate(title="Caso de prueba")
        claims = {"sub": "user-victima-org", "org_id": "org-victima", "type": "access", "role": "analyst"}

        class FakeDb:
            async def commit(self):
                return None

        asyncio.run(main.create_case(payload, claims=claims, db=FakeDb()))

        assert captured["organization_id"] == "org-victima"
        assert captured["actor"] == "user-victima-org"

    def test_attacker_supplied_organization_id_in_json_is_dropped_before_reaching_services(self, monkeypatch):
        # Simula el payload exacto que mandaria un atacante (organization_id
        # de una organizacion que no es la suya) -- pydantic ya lo descarta
        # al parsear porque el campo no existe mas en CaseCreate.
        attacker_json = {"title": "Caso inyectado", "organization_id": "org-victima-ajena"}
        payload = CaseCreate.model_validate(attacker_json)

        captured = {}

        async def fake_create_case(db, payload, organization_id, actor=""):
            captured["organization_id"] = organization_id
            return object()

        monkeypatch.setattr(main.services, "create_case", fake_create_case)
        monkeypatch.setattr(main.cases_created_total.labels(priority="medium", source="manual"), "inc", lambda: None)

        claims = {"sub": "atacante", "org_id": "org-del-atacante", "type": "access", "role": "analyst"}

        class FakeDb:
            async def commit(self):
                return None

        asyncio.run(main.create_case(payload, claims=claims, db=FakeDb()))

        # El organization_id que efectivamente se usa es el del atacante
        # mismo (resuelto de SU JWT), nunca "org-victima-ajena".
        assert captured["organization_id"] == "org-del-atacante"
