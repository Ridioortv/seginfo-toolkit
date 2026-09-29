FROM python:3.11-slim

# Ver main.py para el porque de este servicio: es el UNICO de SentinelOps
# con acceso al socket de Docker (docker-compose.yml lo monta), asi que
# necesita el CLIENTE docker + el plugin de compose -- no la instalacion
# completa de Docker Engine, solo hablar con el daemon del host via el
# socket montado. Se instala desde el repo oficial de Docker (no hay
# paquete `docker-ce-cli` en los repos default de Debian).
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

COPY openvas-orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY openvas-orchestrator/main.py .

HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD curl -f http://localhost:8000/status || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
