"""Modo aislado: el mail no sale y el motivo queda a la vista (no se esconde como un error de red cualquiera)."""
import asyncio
import smtplib
from types import SimpleNamespace

from app import services
from backend.shared import egress


def test_email_is_blocked_in_isolated_mode(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("TERO_ISOLATED_MODE", "1")
    monkeypatch.delenv("TERO_EGRESS_ALLOW", raising=False)
    egress.reset_for_tests()
    opened = []
    monkeypatch.setattr(smtplib, "SMTP", lambda *a, **k: opened.append(a))
    channel = SimpleNamespace(config={"smtp_to": "alguien@empresa.com"})
    status, detail = asyncio.run(services._send_email(channel, "Asunto", "Cuerpo"))
    assert status == "failed" and "modo aislado" in detail and "smtp.gmail.com" in detail
    assert opened == []  # ni siquiera se abrio la conexion
    assert egress.pending()[0]["blocked"] == 1


def test_email_to_an_internal_relay_is_not_reported(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "mail.empresa.lan")
    monkeypatch.setenv("TERO_ISOLATED_MODE", "1")
    egress.reset_for_tests()

    class FakeSMTP:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def send_message(self, msg): self.sent = True

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    channel = SimpleNamespace(config={"smtp_to": "alguien@empresa.com"})
    assert asyncio.run(services._send_email(channel, "Asunto", "Cuerpo")) == ("sent", "")
    assert egress.pending() == []
