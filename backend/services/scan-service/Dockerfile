FROM python:3.11-slim

WORKDIR /app

# nmap se instala directo: es el unico scanner con paquete apt liviano y
# estable. trivy/nuclei/openvas son opcionales -- si no estan presentes el
# driver correspondiente reporta 'scanner_unavailable' en vez de romper el
# servicio (ver app/scanners/base.py ScannerDriver.is_available()).
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl nmap \
    && rm -rf /var/lib/apt/lists/*

COPY backend/services/scan-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/services/scan-service/app ./app
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
