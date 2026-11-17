# case-service: hereda de tero-base (python + dependencias comunes + backend/shared +
# usuario no-root, ver backend/Dockerfile.base). Aca solo va lo propio del servicio.
# Con docker compose la base se construye antes (additional_contexts); suelto:
#   docker build -f backend/Dockerfile.base -t tero-base .
#   docker build -f backend/services/case-service/Dockerfile -t case-service .
ARG BASE_IMAGE=tero-base
FROM ${BASE_IMAGE}

# requirements.txt sigue listando TODAS las dependencias (lo usan pip-audit y CI), pero pip
# salta las que la base ya instalo: solo baja las propias de este servicio.
COPY --chown=sentinelops:sentinelops backend/services/case-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=sentinelops:sentinelops backend/services/case-service/app ./app
COPY --chown=sentinelops:sentinelops backend/services/case-service/tests ./tests

USER sentinelops

HEALTHCHECK --start-period=90s --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
