"""Un nombre repetido, un texto mas largo que la columna o un NUL daban
"500 Internal Server Error"; ahora 409/422 con un mensaje claro y sin
filtrar detalles de la base (backend/shared/db_errors.py)."""
import asyncpg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import DataError, IntegrityError

from backend.shared.db_errors import install_db_error_handlers


def _client(exc):
    app = FastAPI()
    install_db_error_handlers(app)

    @app.get("/boom")
    async def boom():
        raise exc

    return TestClient(app, raise_server_exceptions=False)


def test_unique_violation_is_409_without_internals():
    r = _client(IntegrityError("INSERT INTO secret_table", {}, asyncpg.exceptions.UniqueViolationError("dup"))).get("/boom")
    assert r.status_code == 409
    assert "Ya existe" in r.json()["detail"]
    assert "secret_table" not in r.text and "INSERT" not in r.text


def test_foreign_key_violation_is_409():
    r = _client(IntegrityError("x", {}, asyncpg.exceptions.ForeignKeyViolationError("fk"))).get("/boom")
    assert r.status_code == 409 and "no existe" in r.json()["detail"]


def test_other_integrity_error_is_409():
    r = _client(IntegrityError("x", {}, asyncpg.exceptions.NotNullViolationError("n"))).get("/boom")
    assert r.status_code == 409


@pytest.mark.parametrize("orig", [
    asyncpg.exceptions.StringDataRightTruncationError("too long"),
    asyncpg.exceptions.CharacterNotInRepertoireError("nul"),
])
def test_data_error_is_422(orig):
    r = _client(DataError("INSERT INTO secret_table", {}, orig)).get("/boom")
    assert r.status_code == 422
    assert "secret_table" not in r.text


def _wrapped(cause_cls, msg="x"):
    """Como llega de verdad con asyncpg: DBAPIError cuyo orig es un wrapper
    generico y el error real de asyncpg esta en orig.__cause__."""
    from sqlalchemy.exc import DBAPIError

    class Wrapper(Exception):
        pass

    orig = Wrapper(msg)
    orig.__cause__ = cause_cls(msg)
    return DBAPIError("INSERT INTO secret_table", {}, orig)


def test_generic_dbapi_error_value_too_long_is_422():
    """'value too long for type character varying(255)' llegaba como DBAPIError
    generico (no DataError) y terminaba en 500 (ej. dominio de 300 caracteres)."""
    r = _client(_wrapped(asyncpg.exceptions.StringDataRightTruncationError)).get("/boom")
    assert r.status_code == 422 and "secret_table" not in r.text


def test_generic_dbapi_error_invalid_uuid_is_422():
    r = _client(_wrapped(asyncpg.exceptions.InvalidTextRepresentationError)).get("/boom")
    assert r.status_code == 422


def test_generic_dbapi_error_unique_is_409():
    r = _client(_wrapped(asyncpg.exceptions.UniqueViolationError)).get("/boom")
    assert r.status_code == 409 and "Ya existe" in r.json()["detail"]


def test_other_dbapi_errors_stay_500_without_leaking():
    r = _client(_wrapped(asyncpg.exceptions.DeadlockDetectedError)).get("/boom")
    assert r.status_code == 500 and "secret_table" not in r.text
