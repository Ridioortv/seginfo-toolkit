"""Tests de app/services.py::is_deletable_status -- la regla de negocio que
decide si un escaneo (propio o de agente remoto) ya se puede borrar. Sin
DB: solo logica pura, igual que test_nmap_driver.py en este mismo paquete."""
import enum

from app.services import is_deletable_status


class _FakeStatusEnum(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    scanner_unavailable = "scanner_unavailable"


class TestIsDeletableStatus:
    def test_terminal_string_statuses_are_deletable(self):
        assert is_deletable_status("completed") is True
        assert is_deletable_status("failed") is True
        assert is_deletable_status("scanner_unavailable") is True

    def test_in_progress_string_statuses_are_not_deletable(self):
        assert is_deletable_status("pending") is False
        assert is_deletable_status("running") is False

    def test_accepts_enum_members_not_just_strings(self):
        # job.status llega como el enum de SQLAlchemy, no como str plano --
        # is_deletable_status tiene que manejar ambos (ver hasattr(.., "value")).
        assert is_deletable_status(_FakeStatusEnum.completed) is True
        assert is_deletable_status(_FakeStatusEnum.running) is False

    def test_unknown_status_is_not_deletable(self):
        assert is_deletable_status("some_future_status") is False
