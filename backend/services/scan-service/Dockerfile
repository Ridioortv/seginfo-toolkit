FROM python:3.11-slim

WORKDIR /app

# trivy/nuclei/gitleaks/zap se instalan aparte mas abajo (no tienen
# paquete apt en Debian) -- gcc/libpq-dev son para compilar dependencias
# Python nativas, curl/unzip/git/gnupg son herramientas de instalacion
# que usan los pasos de abajo (git: clona repos para semgrep/gitleaks
# cuando el target es una URL, ver app/scanners/_codetarget.py; gnupg:
# agrega las claves de los repos apt de zeek/falco mas abajo). yara SI
# tiene paquete apt en Debian -- se instala directo aca, sin pasos
# propios.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev curl unzip git gnupg yara libcap2-bin \
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

# --- Sumados por directiva de expansion comercial (Manu, 2026) ---------
# Unicamente herramientas cuya licencia permite venderlas como parte de
# este producto -- ver el documento "Directivas de Expansion Comercial y
# Licencias" y el docstring de cada driver en app/scanners/ para el
# detalle de licencia/alcance por herramienta.

# Gitleaks (secretos/credenciales en historial de git, MIT): mismo
# patron que nuclei arriba -- no tiene paquete apt, se resuelve la
# ultima release de GitHub en build-time. Mismo mecanismo ya probado en
# produccion en coderepo-service/Dockerfile.
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") \
    && curl -sSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

# OWASP ZAP (DAST pasivo, Apache 2.0): necesita un JRE -- default-jre-
# headless se instala aparte (no en el apt-get de mas arriba, para que
# quede clara la relacion 1 a 1 con este paso). El tarball "Linux" de la
# ultima release de GitHub se resuelve dinamicamente (el nombre del
# asset trae la version en el medio, ej. "ZAP_2.16.1_Linux.tar.gz") en
# vez de hardcodear una URL que quede vieja.
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
RUN ZAP_ASSET_URL=$(curl -s https://api.github.com/repos/zaproxy/zaproxy/releases/latest \
        | python3 -c "import sys, json; d=json.load(sys.stdin); print(next(a['browser_download_url'] for a in d['assets'] if a['name'].endswith('_Linux.tar.gz')))") \
    && curl -sSL -o /tmp/zap.tar.gz "$ZAP_ASSET_URL" \
    && mkdir -p /opt/zap \
    && tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 \
    && chmod +x /opt/zap/zap.sh \
    && ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh \
    && rm /tmp/zap.tar.gz
# Directorio de configuracion/estado de ZAP (ver app/scanners/zap.py,
# ZAP_HOME_DIR) -- tiene que existir y ser escribible por el usuario
# no-root 'sentinelops' (chown mas abajo, junto con el resto).
RUN mkdir -p /home/sentinelops/.ZAP

# Zeek (captura/analisis pasivo de red, BSD-3-Clause): no tiene release
# binaria suelta como trivy/nuclei/gitleaks -- se instala desde el repo
# apt oficial del proyecto (Open Build Service), eligiendo la ruta del
# repo segun la version de Debian de ESTA imagen base (en vez de
# hardcodear "Debian_12", que se rompe si python:3.11-slim migra a otra
# version de Debian). Envuelto en un fallback no-fatal: si el repo/la
# key no estan disponibles en este momento, el build sigue (zeek queda
# reportado como "no disponible" en runtime, ver
# app/scanners/base.py::is_available -- nunca se degrada en silencio a
# "no encontro nada" durante un escaneo real, solo durante el build).
RUN . /etc/os-release \
    && (curl -fsSL "https://download.opensuse.org/repositories/security:zeek/Debian_${VERSION_ID}/Release.key" \
            | gpg --dearmor -o /usr/share/keyrings/zeek-archive-keyring.gpg \
        && echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_${VERSION_ID}/ /" \
            > /etc/apt/sources.list.d/zeek.list \
        && apt-get update \
        && apt-get install -y --no-install-recommends zeek \
        && rm -rf /var/lib/apt/lists/*) \
    || echo "ADVERTENCIA (build): no se pudo instalar zeek -- el scanner 'zeek' va a quedar reportado como no disponible hasta que se resuelva esto."
ENV PATH="/opt/zeek/bin:${PATH}"

# Capability de archivo para que zeek pueda abrir sockets raw (captura de
# paquetes) corriendo como el usuario NO-root "sentinelops" (ver USER mas
# abajo) -- docker-compose.yml le da NET_RAW/NET_ADMIN al CONTENEDOR via
# cap_add, pero eso solo las agrega al "bounding set"; un proceso no-root
# NO las tiene en su set efectivo a menos que el binario las tenga
# marcadas asi (bug real encontrado en produccion: zeek fallaba con
# "pcap_activate: Operation not permitted" pese al cap_add). No-fatal: si
# el binario no existe (el paso de arriba fallo) o setcap no esta
# disponible, zeek sigue quedando "no disponible" en vez de romper el build.
RUN setcap cap_net_raw,cap_net_admin+eip /opt/zeek/bin/zeek 2>/dev/null \
    || echo "ADVERTENCIA (build): no se pudo aplicar setcap a zeek (el binario puede no existir todavia) -- va a fallar en runtime con 'Operation not permitted' al capturar."

# Falco (monitoreo de runtime via eBPF, Apache 2.0): repo apt oficial de
# falcosecurity. Igual que zeek arriba, envuelto en un fallback no-fatal
# -- ademas de que el repo pueda no estar disponible en build-time,
# Falco es el que mas depende de capacidades del kernel del HOST en
# runtime (ver docker-compose.yml, cap_add) para poder arrancar de
# verdad, asi que instalarlo aca es necesario pero no suficiente.
RUN (curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
            | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg \
        && echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
            > /etc/apt/sources.list.d/falcosecurity.list \
        && apt-get update \
        && apt-get install -y --no-install-recommends falco \
        && rm -rf /var/lib/apt/lists/*) \
    || echo "ADVERTENCIA (build): no se pudo instalar falco -- el scanner 'falco' va a quedar reportado como no disponible hasta que se resuelva esto."

COPY backend/services/scan-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Reglas PROPIAS de SentinelOps para semgrep/yara -- NUNCA un ruleset de
# terceros (ver rules/semgrep/sentinelops-rules.yml y
# rules/yara/sentinelops.yar para el porque exacto de cada caso). Las
# usan app/scanners/semgrep.py (SEMGREP_RULES_DIR) y
# app/scanners/yara.py (YARA_RULES_FILE) respectivamente.
COPY backend/services/scan-service/rules/semgrep /opt/sentinelops-semgrep-rules
COPY backend/services/scan-service/rules/yara /opt/sentinelops-yara-rules

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
# ya no hay ningun subproceso que necesite ese truco por ese motivo --
# trivy/nuclei/gitleaks/zap/semgrep/yara nunca lo necesitaron -- asi que
# este contenedor pasa al mismo patron no-root que los demas servicios
# del backend. zeek/falco SI necesitan privilegios de kernel en runtime,
# pero eso se resuelve via capabilities de Linux otorgadas al
# CONTENEDOR (ver docker-compose.yml, cap_add) -- un usuario no-root
# DENTRO del contenedor puede usar esas capabilities igual, no hace
# falta volver a correr como root por esto.
# chmod 755 /root (ademas del chown -R de las subcarpetas): varios
# escaneres escriben sus caches/config bajo /root/... (ver
# docker-compose.yml, volumenes) -- sin abrir el propio directorio
# /root (modo 700 por default en esta imagen base), el usuario
# sentinelops no puede ni ATRAVESARLO para llegar a esas subcarpetas,
# aunque esten chowneadas, y esos escaneres fallarian con Permission
# denied en el primer uso.
RUN groupadd -r -g 1001 sentinelops && useradd -r -u 1001 -g sentinelops -M -s /usr/sbin/nologin sentinelops \
    && chmod 755 /root \
    && chown -R sentinelops:sentinelops /app /root/.cache/trivy /root/nuclei-templates /home/sentinelops \
    && chmod -R a+rX /opt/sentinelops-semgrep-rules /opt/sentinelops-yara-rules
USER sentinelops

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
