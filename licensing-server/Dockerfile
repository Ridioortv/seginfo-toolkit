FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY licensing-server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY licensing-server/app ./app

# La base SQLite vive en un volumen (ver docker-compose.licensing.yml) --
# si el contenedor se recrea sin ese volumen, se pierden todas las
# licencias emitidas.
ENV LICENSING_DB_PATH=/data/licensing.db
VOLUME ["/data"]

RUN groupadd -r -g 1001 licensing && useradd -r -u 1001 -g licensing -M -s /usr/sbin/nologin licensing \
    && mkdir -p /data && chown -R licensing:licensing /app /data
USER licensing

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
