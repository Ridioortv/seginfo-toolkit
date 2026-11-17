"""Una regla con `condition` vacia, mal escrita o que nombra un selection
inexistente se guardaba "activa" pero nunca disparaba (evaluate_rule la
descartaba en silencio). Ahora la API la rechaza al crearla/editarla."""
import pytest
from pydantic import ValidationError

from app.schemas import SigmaRuleCreate, SigmaRuleUpdate
from app.sigma import validate_detection

OK = {"sel": {"user.name": "root"}, "condition": "sel"}


class TestValidateDetection:
    def test_valid_rule_passes(self):
        assert validate_detection(OK) is OK
        validate_detection({"a": {"x": 1}, "b": {"y": [1, 2]}, "condition": "a and not b or a"})

    @pytest.mark.parametrize("bad", [
        {"sel": {"a": "b"}},                                  # sin condition
        {"sel": {"a": "b"}, "condition": ""},                 # condition vacia
        {"sel": {"a": "b"}, "condition": "   "},
        {"condition": "sel"},                                 # sin selections
        {"sel": {"a": "b"}, "condition": "otro"},             # selection inexistente
        {"sel": {"a": "b"}, "condition": "sel and or"},       # sintaxis rota
        {"sel": {"a": "b"}, "condition": "sel + 1"},          # operador no permitido
        {"sel": {"a": "b"}, "condition": "__import__('os')"},  # llamada
        {"sel": {"a": "b"}, "condition": "x" * 501},          # demasiado larga
        {"sel": {}, "condition": "sel"},                      # selection vacio
        {"sel": "texto", "condition": "sel"},                 # selection no es objeto
        {"sel": {"a": "b"}, "condition": 5},                  # condition no es texto
    ])
    def test_invalid_rules_are_rejected(self, bad):
        with pytest.raises(ValueError):
            validate_detection(bad)

    def test_not_a_dict(self):
        with pytest.raises(ValueError):
            validate_detection([])


class TestSchemasUseIt:
    def test_create_rejects_bad_detection(self):
        with pytest.raises(ValidationError):
            SigmaRuleCreate(name="r", detection={"condition": "inexistente"})

    def test_create_accepts_good_detection(self):
        assert SigmaRuleCreate(name="r", detection=OK).detection == OK

    def test_update_validates_only_when_given(self):
        assert SigmaRuleUpdate(is_enabled=False).detection is None
        with pytest.raises(ValidationError):
            SigmaRuleUpdate(detection={"sel": {"a": "b"}, "condition": "zzz"})

    def test_default_and_antiestafa_rules_are_valid(self):
        from app import antiestafa
        from app.services import DEFAULT_RULES
        for spec in DEFAULT_RULES + antiestafa.RULES:
            validate_detection(spec["detection"])
