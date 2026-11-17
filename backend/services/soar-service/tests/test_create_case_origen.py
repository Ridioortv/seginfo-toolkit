"""create_case manda source='soar': los casos de SOAR figuraban con origen 'manual'."""
import asyncio

import httpx

from app.actions import create_case as mod


def test_case_is_created_with_soar_source(monkeypatch):
    seen = {}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            seen["json"] = json
            return httpx.Response(201, json={"id": "c1"})

    monkeypatch.setattr(mod, "CASE_SERVICE_URL", "http://case-service:8000")
    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(mod, "service_auth_headers", lambda org: {})
    action = mod.CreateCaseAction()
    result = asyncio.run(action.execute({}, {"alert": {"id": "a1", "severity": "high", "rule_name": "r"}, "organization_id": "o1"}))
    assert result.success
    assert seen["json"]["source"] == "soar"
