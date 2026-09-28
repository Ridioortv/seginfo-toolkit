"""Structured JSON logging shared across services."""
import logging
import sys
import json
import time
import uuid
from contextvars import ContextVar

correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


# Atributos estandar que logging.LogRecord siempre trae -- todo lo que un
# logger.info(..., extra={...}) agrega queda COMO ATRIBUTOS SUELTOS del
# record (no en un dict separado), asi que la unica forma de recuperar
# esos extras es diffear record.__dict__ contra este set. Sin esto (bug
# real: el formatter de abajo los ignoraba por completo desde siempre),
# cada logger.info("x", extra={"job_id": ...}) de todo el codebase perdia
# el job_id/agent_name/org/etc en el output -- los logs solo mostraban el
# mensaje generico, nunca el detalle que se le paso.
_STANDARD_RECORD_ATTRS = frozenset(logging.LogRecord(
    "", logging.INFO, "", 0, "", None, None,
).__dict__.keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON with a correlation id."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id_var.get() or None,
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_ATTRS and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(service_name: str) -> logging.Logger:
    logger = logging.getLogger(service_name)
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def new_correlation_id() -> str:
    cid = str(uuid.uuid4())
    correlation_id_var.set(cid)
    return cid
