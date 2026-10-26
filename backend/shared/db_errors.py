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
from sqlalchemy.exc import DataError, IntegrityError

logger = logging.getLogger(__name__)


def _orig_name(exc) -> str:
    orig = getattr(exc, "orig", None)
    return type(orig).__name__ if orig is not None else ""


async def _integrity_error(request: Request, exc: IntegrityError):
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


def install_db_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(IntegrityError, _integrity_error)
    app.add_exception_handler(DataError, _data_error)
