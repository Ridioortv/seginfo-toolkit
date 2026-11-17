"""La API de casos aceptaba titulo vacio y textos mas largos que la columna
(500 de la base en vez de 422)."""
import pytest
from pydantic import ValidationError

from app.schemas import CaseCreate, CaseUpdate, TimelineEntryCreate


class TestCaseTitle:
    @pytest.mark.parametrize("bad", ["", "   ", "\n\t"])
    def test_empty_title_rejected(self, bad):
        with pytest.raises(ValidationError):
            CaseCreate(title=bad)
        with pytest.raises(ValidationError):
            CaseUpdate(title=bad)

    def test_title_is_trimmed(self):
        assert CaseCreate(title="  Intrusion  ").title == "Intrusion"

    def test_update_without_title_is_fine(self):
        assert CaseUpdate(status="closed").title is None

    def test_too_long_values_are_rejected(self):
        with pytest.raises(ValidationError):
            CaseCreate(title="x" * 501)
        with pytest.raises(ValidationError):
            CaseCreate(title="ok", assignee="a" * 256)
        with pytest.raises(ValidationError):
            CaseCreate(title="ok", source="s" * 51)
        with pytest.raises(ValidationError):
            CaseUpdate(title="x" * 501)


class TestTimeline:
    def test_empty_action_rejected(self):
        for bad in ("", "  "):
            with pytest.raises(ValidationError):
                TimelineEntryCreate(action=bad)

    def test_too_long_action_rejected(self):
        with pytest.raises(ValidationError):
            TimelineEntryCreate(action="a" * 101)

    def test_ok(self):
        assert TimelineEntryCreate(action=" nota ").action == "nota"
