# --- Etapa 1: build estatico (Vite) ----------------------------------------
FROM node:25-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# npm ci = instalacion reproducible desde el lockfile (el CI audita ese mismo lock)
RUN npm ci --no-audit --no-fund
COPY . .

# Las URLs de las APIs se "hornean" en el bundle en build time (Vite las lee de
# import.meta.env). Defaults = stack local. Se sobreescriben desde docker-compose
# (build.args) con los valores de .env.
ARG VITE_GOOGLE_CLIENT_ID=""
ARG VITE_API_BASE_URL=http://localhost:8001
ARG VITE_ASSET_API_BASE_URL=http://localhost:8002
ARG VITE_SCAN_API_BASE_URL=http://localhost:8003
ARG VITE_VULN_API_BASE_URL=http://localhost:8004
ARG VITE_SIEM_API_BASE_URL=http://localhost:8005
ARG VITE_SOAR_API_BASE_URL=http://localhost:8006
ARG VITE_CASE_API_BASE_URL=http://localhost:8007
ARG VITE_PURPLE_API_BASE_URL=http://localhost:8008
ARG VITE_REPORT_API_BASE_URL=http://localhost:8009
ARG VITE_NOTIFICATION_API_BASE_URL=http://localhost:8010
ARG VITE_INTEGRATION_API_BASE_URL=http://localhost:8011
ARG VITE_THREATINTEL_API_BASE_URL=http://localhost:8012
ARG VITE_ASM_API_BASE_URL=http://localhost:8013
ARG VITE_CLOUD_API_BASE_URL=http://localhost:8014
ARG VITE_CODEREPO_API_BASE_URL=http://localhost:8015
ENV VITE_GOOGLE_CLIENT_ID=$VITE_GOOGLE_CLIENT_ID \
    VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_ASSET_API_BASE_URL=$VITE_ASSET_API_BASE_URL \
    VITE_SCAN_API_BASE_URL=$VITE_SCAN_API_BASE_URL \
    VITE_VULN_API_BASE_URL=$VITE_VULN_API_BASE_URL \
    VITE_SIEM_API_BASE_URL=$VITE_SIEM_API_BASE_URL \
    VITE_SOAR_API_BASE_URL=$VITE_SOAR_API_BASE_URL \
    VITE_CASE_API_BASE_URL=$VITE_CASE_API_BASE_URL \
    VITE_PURPLE_API_BASE_URL=$VITE_PURPLE_API_BASE_URL \
    VITE_REPORT_API_BASE_URL=$VITE_REPORT_API_BASE_URL \
    VITE_NOTIFICATION_API_BASE_URL=$VITE_NOTIFICATION_API_BASE_URL \
    VITE_INTEGRATION_API_BASE_URL=$VITE_INTEGRATION_API_BASE_URL \
    VITE_THREATINTEL_API_BASE_URL=$VITE_THREATINTEL_API_BASE_URL \
    VITE_ASM_API_BASE_URL=$VITE_ASM_API_BASE_URL \
    VITE_CLOUD_API_BASE_URL=$VITE_CLOUD_API_BASE_URL \
    VITE_CODEREPO_API_BASE_URL=$VITE_CODEREPO_API_BASE_URL
RUN npm run build

# --- Etapa 2: nginx SIN privilegios sirviendo solo archivos estaticos -------
# (antes corria el servidor de desarrollo de Vite como root: sin minificar,
# con HMR y con sus CVEs de file-read/path-traversal expuestas en la red)
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
USER nginx
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:8080/ || exit 1
