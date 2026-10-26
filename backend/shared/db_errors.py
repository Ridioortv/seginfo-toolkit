"""Manejo comun de errores de base de datos causados por DATOS del usuario.

Antes, un valor que la base rechaza (un nombre repetido que viola una
restriccion unica, un texto mas largo que la columna, un caracter NUL) subia
como excepcion de SQLAlchemy y el usuario veia "500 Internal Server Error"
sin pista de que corregir. Con esto responden 409 / 422 con un mensaje claro y
sin filtrar detalles internos de la base (nombres de tablas, SQL).

Uso en cada servicio:  install_db_error_handlers(app)
"""
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError

logger = logging.getLogger(__name__)


def _orig_name(exc) -> str:
    """Nombre de la clase del error REAL de asyncpg (UniqueViolationError, etc.).
    SQLAlchemy lo envuelve en un error generico y deja el original en __cause__."""
    orig = getattr(exc, "orig", None)
    cause = getattr(orig, "__cause__", None)
    target = cause if cause is not None else orig
    return type(target).__name__ if target is not None else ""


async def _integrity_error(request: Request, exc: DBAPIError):
    kind = _orig_name(exc)
    logger.warning("integridad de datos violada", extra={"path": request.url.path, "kind": kind})
    if "Unique" in kind:
        detail = "Ya existe un registro con esos datos (nombre o identificador repetido)."
    elif "ForeignKey" in kind:
        detail = "Hace referencia a un registro que no existe."
    else:
        detail = "Los datos enviados no son validos para este registro."
    return JSONResponse(status_code=409, content={"detail": detail})


async def _data_error(request: Request, exc: DataError):
    logger.warning("dato rechazado por la base", extra={"path": request.url.path, "kind": _orig_name(exc)})
    return JSONResponse(
        status_code=422,
        content={"detail": "Algun valor es demasiado largo, tiene caracteres no validos o un formato incorrecto."},
    )


def _sqlstate(exc) -> str:
    """SQLSTATE del error de Postgres. Con asyncpg, SQLAlchemy solo traduce
    algunas clases a DataError/IntegrityError; por ejemplo "value too long for
    type character varying" (22001) llega como DBAPIError generico y el
    codigo esta en orig.__cause__.sqlstate."""
    orig = getattr(exc, "orig", None)
    for obj in (orig, getattr(orig, "__cause__", None)):
        code = getattr(obj, "sqlstate", None) or getattr(obj, "pgcode", None)
        if code:
            return str(code)
    return ""


async def _dbapi_error(request: Request, exc: DBAPIError):
    code = _sqlstate(exc)
    if code.startswith("22"):  # data_exception: demasiado largo, NUL, formato (uuid, fecha, numero)...
        return await _data_error(request, exc)
    if code.startswith("23"):  # integrity_constraint_violation
        return await _integrity_error(request, exc)
    logger.exception("error de base de datos", extra={"path": request.url.path, "sqlstate": code})
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


def install_db_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(DBAPIError, _dbapi_error)
    app.add_exception_handler(IntegrityError, _integrity_error)
    app.add_exception_handler(DataError, _data_error)
