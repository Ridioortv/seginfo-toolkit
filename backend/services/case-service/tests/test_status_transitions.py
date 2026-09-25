"""Tests de app/services.py::is_valid_status_transition -- la regla de
negocio que decide si un caso puede pasar de un status a otro via PATCH
/cases/{case_id}. Mismo grafo que STATUS_TRANSITIONS en
frontend/src/pages/Cases.tsx (open<->in_progress, in_progress<->resolved,
resolved<->closed, closed->open). Sin DB: solo logica pura, igual que
test_delete_status.py en scan-service."""
import enum

from app.models import CaseStatus
from app.services import is_valid_status_transition


class _FakeStatusEnum(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    resolved = "resolved"
    closed = "closed"


class TestIsValidStatusTransition:
    def test_frontend_offered_transitions_are_all_valid(self):
        # Mismo grafo que STATUS_TRANSITIONS en Cases.tsx.
        assert is_valid_status_transition("open", "in_progress") is True
        assert is_valid_status_transition("in_progress", "resolved") is True
        assert is_valid_status_transition("in_progress", "open") is True
        assert is_valid_status_transition("resolved", "closed") is True
        assert is_valid_status_transition("resolved", "in_progress") is True
        assert is_valid_status_transition("closed", "open") is True

    def test_transitions_the_frontend_never_offers_are_rejected(self):
        # Nada salta directo de open a resolved/closed, ni de closed a
        # cualquier cosa que no sea open.
        assert is_valid_status_transition("open", "resolved") is False
        assert is_valid_status_transition("open", "closed") is False
        assert is_valid_status_transition("closed", "in_progress") is False
        assert is_valid_status_transition("closed", "resolved") is False
        assert is_valid_status_transition("resolved", "open") is False

    def test_staying_on_the_same_status_is_always_valid(self):
        # No-op: el payload puede mandar el status actual sin que eso sea
        # una transicion real (ver update_case, que solo dispara el
        # timeline entry "case.status_changed" cuando cambia de verdad).
        for status in CaseStatus:
            assert is_valid_status_transition(status.value, status.value) is True

    def test_accepts_enum_members_not_just_strings(self):
        # case.status llega como el enum de SQLAlchemy (CaseStatus), y el
        # payload trae CaseStatus tambien (pydantic ya lo valido) -- ambos
        # tienen que funcionar igual que con str plano.
        assert is_valid_status_transition(CaseStatus.open, CaseStatus.in_progress) is True
        assert is_valid_status_transition(CaseStatus.open, CaseStatus.closed) is False
        assert is_valid_status_transition(_FakeStatusEnum.resolved, _FakeStatusEnum.closed) is True

    def test_unknown_status_has_no_valid_outgoing_transition(self):
        assert is_valid_status_transition("some_future_status", "open") is False
