FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/services/auth-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/services/auth-service/app ./app
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
