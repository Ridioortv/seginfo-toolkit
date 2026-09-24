FROM python:3.11-slim

WORKDIR /app

# nmap: paquete apt liviano y estable. trivy y nuclei se instalan aparte
# mas abajo (no tienen paquete apt en Debian). openvas/gvm-cli sigue sin
# instalarse a proposito: no es un binario CLI suelto, sino un producto
# completo (gvmd + su propia base de datos + sincronizacion de feed de
# NVTs) -- empaquetarlo aca seria un proyecto en si mismo. Por eso su
# driver reporta 'scanner_unavailable' en vez de romper el servicio (ver
# app/scanners/base.py ScannerDriver.is_available() y openvas.py).
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl nmap unzip \
    && rm -rf /var/lib/apt/lists/*

# Trivy (CVEs conocidos en imagenes de contenedor / filesystems): script
# oficial de aquasecurity, instala el binario mas reciente en
# /usr/local/bin.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Nuclei (deteccion basada en plantillas): no tiene paquete apt ni script
# de instalacion propio como el de trivy, asi que se resuelve la ultima
# release de GitHub en build-time (para no hardcodear una version que
# quede vieja) y se descarga el binario ya compilado para linux_amd64.
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") \
    && curl -sSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

COPY backend/services/scan-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/services/scan-service/app ./app
COPY backend/services/scan-service/tests ./tests
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
