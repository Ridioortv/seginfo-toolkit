"""Un min_severity desconocido (ej. "ultra") tenia rango 0 y el playbook
disparaba con CUALQUIER alerta; los pasos con accion inexistente solo fallaban
al ejecutar. Ahora se rechazan al crear/editar."""
import pytest
from pydantic import ValidationError

from app.schemas import PlaybookCreate, PlaybookUpdate


@pytest.mark.parametrize("cls", [PlaybookCreate, PlaybookUpdate])
class TestMinSeverity:
    def kw(self, cls, **k):
        return dict(name="p", **k) if cls is PlaybookCreate else k

    @pytest.mark.parametrize("bad", ["ultra", "", "alta", "5"])
    def test_unknown_rejected(self, cls, bad):
        with pytest.raises(ValidationError):
            cls(**self.kw(cls, min_severity=bad))

    @pytest.mark.parametrize("good,norm", [("high", "high"), (" CRITICAL ", "critical"), ("info", "info")])
    def test_valid_normalized(self, cls, good, norm):
        assert cls(**self.kw(cls, min_severity=good)).min_severity == norm


@pytest.mark.parametrize("cls", [PlaybookCreate, PlaybookUpdate])
class TestSteps:
    def kw(self, cls, **k):
        return dict(name="p", **k) if cls is PlaybookCreate else k

    def test_unknown_action_rejected(self, cls):
        with pytest.raises(ValidationError):
            cls(**self.kw(cls, steps=[{"action": "formatear_disco"}]))

    def test_missing_action_rejected(self, cls):
        with pytest.raises(ValidationError):
            cls(**self.kw(cls, steps=[{"params": {}}]))

    def test_params_must_be_object(self, cls):
        with pytest.raises(ValidationError):
            cls(**self.kw(cls, steps=[{"action": "notify", "params": "x"}]))

    def test_known_actions_ok(self, cls):
        steps = [{"action": a, "params": {}} for a in ("block_ip", "isolate_host", "create_case", "create_ticket", "notify")]
        assert len(cls(**self.kw(cls, steps=steps)).steps) == 5
