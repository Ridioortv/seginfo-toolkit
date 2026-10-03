FROM python:3.11-slim

WORKDIR /app

# trivy y nuclei se instalan aparte mas abajo (no tienen paquete apt en
# Debian) -- gcc/libpq-dev son para compilar dependencias Python nativas,
# curl/unzip son herramientas de instalacion que usan los pasos de abajo.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Trivy (CVEs conocidos en imagenes de contenedor / filesystems): script
# oficial de aquasecurity, instala el binario mas reciente en
# /usr/local/bin.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Baja la base de datos de CVEs UNA VEZ en build-time (no en cada escaneo:
# ver app/scanners/trivy.py, que corre con --skip-db-update). Se persiste
# despues en el volumen nombrado `trivy_cache` (ver docker-compose.yml) --
# Docker copia este contenido de la imagen al volumen la primera vez que
# se monta, asi que el primer arranque ya tiene la DB lista sin esperar
# nada. Un job periodico (app/services.py::refresh_trivy_db) la mantiene
# actualizada despues.
RUN mkdir -p /root/.cache/trivy && trivy image --download-db-only --cache-dir /root/.cache/trivy

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

# NUCLEI_TEMPLATES_DIR fijo (en vez de dejar que nuclei elija por defecto
# via XDG, que puede variar entre versiones) para que el volumen nombrado
# `nuclei_templates` (ver docker-compose.yml) siempre apunte al lugar
# correcto. Baja las plantillas UNA VEZ en build-time (no en cada escaneo:
# ver app/scanners/nuclei.py, que corre con -duc); se persisten despues
# (mismo mecanismo de copia-al-primer-montaje que trivy_cache, arriba).
# Un job periodico (app/services.py::refresh_nuclei_templates) las
# mantiene actualizadas.
ENV NUCLEI_TEMPLATES_DIR=/root/nuclei-templates
RUN nuclei -update-templates -silent || true

COPY backend/services/scan-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY backend/services/scan-service/app ./app
COPY backend/services/scan-service/tests ./tests
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

# A diferencia del resto de este Dockerfile hasta ahora: scan-service
# corria como root porque gvm-cli (gvm-tools) necesitaba arrancar como
# root para poder bajar sus propios privilegios a 'nobody' via setuid/
# setgid antes del exec (gvmtools/helper.py se niega EXPLICITAMENTE a
# correr como root, pero SI necesitaba serlo un instante antes). Sin GVM
# ya no hay ningun subproceso que necesite ese truco -- trivy/nuclei
# nunca lo necesitaron -- asi que este contenedor pasa al mismo patron
# no-root que los demas 14 servicios del backend.
# chmod 755 /root (ademas del chown -R de las dos subcarpetas): trivy/
# nuclei escriben sus caches en /root/.cache/trivy y /root/nuclei-templates
# (ver docker-compose.yml, volumenes trivy_cache/nuclei_templates) -- sin
# abrir el propio directorio /root (modo 700 por default en esta imagen
# base), el usuario sentinelops no puede ni ATRAVESARLO para llegar a esas
# subcarpetas, aunque esas dos esten chowneadas, y trivy/nuclei fallarian
# con Permission denied en el primer escaneo.
RUN groupadd -r -g 1001 sentinelops && useradd -r -u 1001 -g sentinelops -M -s /usr/sbin/nologin sentinelops \
    && chmod 755 /root \
    && chown -R sentinelops:sentinelops /app /root/.cache/trivy /root/nuclei-templates
USER sentinelops

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
