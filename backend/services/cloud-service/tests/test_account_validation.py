"""Se aceptaban cuentas con nombre vacio, region inexistente y claves de 1
caracter; el error recien aparecia al sincronizar."""
import pytest
from pydantic import ValidationError

from app.schemas import CloudAccountCreate

OK = dict(name="aws-prod", region="sa-east-1", access_key_id="AKIAIOSFODNN7EXAMPLE",
          secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


def test_valid_account_accepted_and_trimmed():
    acc = CloudAccountCreate(**{**OK, "name": "  aws-prod  ", "region": " SA-EAST-1 "})
    assert acc.name == "aws-prod" and acc.region == "sa-east-1"


@pytest.mark.parametrize("field,bad", [
    ("name", ""), ("name", "   "), ("name", "x" * 256),
    ("region", "mars"), ("region", "us_east_1"), ("region", ""),
    ("access_key_id", "A"), ("access_key_id", "akia-lowercase-bad!"),
    ("secret_access_key", "corta"), ("secret_access_key", "con espacios " * 4),
])
def test_invalid_values_rejected(field, bad):
    with pytest.raises(ValidationError):
        CloudAccountCreate(**{**OK, field: bad})


def test_default_region_is_valid():
    d = {k: v for k, v in OK.items() if k != "region"}
    assert CloudAccountCreate(**d).region == "us-east-1"
