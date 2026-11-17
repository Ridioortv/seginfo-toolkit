"""Cliente compartido que usan los demas servicios para anotar eventos: nunca rompe el flujo, reintenta en cola."""
import asyncio

import httpx
import pytest

from backend.shared import custody


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("TERO_CUSTODY_DISABLED", raising=False)
    custody._QUEUE.clear()
    yield
    custody._QUEUE.clear()


def run(coro):
    return asyncio.run(coro)


def test_digest_is_stable_and_order_independent():
    assert custody.digest({"a": 1, "b": [1, 2]}) == custody.digest({"b": [1, 2], "a": 1})
    assert custody.digest({"a": 1}) != custody.digest({"a": 2})
    assert len(custody.digest("x")) == 64


def test_disabled_does_nothing(monkeypatch):
    monkeypatch.setenv("TERO_CUSTODY_DISABLED", "1")

    async def boom(*a, **k):
        raise AssertionError("no debe intentar la red")

    monkeypatch.setattr(custody, "_deliver", boom)
    assert run(custody.record_event("alert.created", service="siem-service", organization_id="o")) is False
    assert custody.pending_events() == 0


def test_delivered_event_sends_expected_body(monkeypatch):
    sent = []

    async def post(client, service, org, body):
        sent.append((service, org, body))
        return True

    monkeypatch.setattr(custody, "_post", post)
    ok = run(custody.record_event("alert.created", service="siem-service", organization_id="org-1", actor="x",
                                  subject_type="alert", subject_id="a1", refs=["alert:a1"], payload={"k": 1}))
    assert ok and custody.pending_events() == 0
    service, org, body = sent[0]
    assert (service, org) == ("siem-service", "org-1")
    assert body == {"event_type": "alert.created", "actor": "x", "source": "siem-service", "subject_type": "alert",
                    "subject_id": "a1", "refs": ["alert:a1"], "payload": {"k": 1}}


def test_failure_queues_and_never_raises_then_retries(monkeypatch):
    calls = {"ok": False, "n": 0}

    async def post(client, service, org, body):
        calls["n"] += 1
        return calls["ok"]

    monkeypatch.setattr(custody, "_post", post)
    assert run(custody.record_event("scan.completed", service="scan-service", organization_id="o")) is False
    assert run(custody.record_event("scan.completed", service="scan-service", organization_id="o")) is False
    assert custody.pending_events() == 2
    calls["ok"] = True
    assert run(custody.record_event("scan.completed", service="scan-service", organization_id="o")) is True
    assert custody.pending_events() == 0


def test_queue_is_bounded(monkeypatch):
    async def post(*a, **k):
        return False

    from collections import deque

    monkeypatch.setattr(custody, "_post", post)
    monkeypatch.setattr(custody, "_QUEUE", deque(maxlen=5))
    for _ in range(12):
        run(custody.record_event("scan.completed", service="scan-service", organization_id="o"))
    assert custody.pending_events() == 5


def test_unexpected_exception_is_swallowed(monkeypatch):
    async def deliver(*a, **k):
        raise RuntimeError("explotó")

    monkeypatch.setattr(custody, "_deliver", deliver)
    assert run(custody.record_event("scan.completed", service="scan-service", organization_id="o")) is False
    assert custody.pending_events() == 1


def test_post_treats_5xx_as_retry_and_4xx_as_final():
    class Resp:
        def __init__(self, code):
            self.status_code, self.text = code, "x"

    class Client:
        def __init__(self, code=None, exc=None):
            self.code, self.exc = code, exc

        async def post(self, *a, **k):
            if self.exc:
                raise self.exc
            return Resp(self.code)

    body = {"event_type": "alert.created"}
    assert run(custody._post(Client(201), "s", "o", body)) is True
    assert run(custody._post(Client(403), "s", "o", body)) is True
    assert run(custody._post(Client(503), "s", "o", body)) is False
    assert run(custody._post(Client(exc=httpx.ConnectError("x")), "s", "o", body)) is False
