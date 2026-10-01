#!/usr/bin/env bash
# Configura el Agente OpenVAS una vez que los feeds terminaron de
# sincronizar (ver README.md paso 1): crea el usuario admin de GVM y
# guarda sus credenciales en .env. Correr desde esta misma carpeta
# (remote-agent/openvas-agent/), equivalente en bash de openvas/
# Configurar-OpenVAS.ps1 (que hace lo mismo para el stack principal).
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "No se encontro 'docker'. Instalalo y reintenta." >&2
  exit 1
fi

if ! docker compose ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -q '^gvmd '; then
  echo "gvmd no esta corriendo. Corre primero 'docker compose up -d' y espera a que sincronice" >&2
  echo "(20-40 min la primera vez -- segui el progreso con 'docker compose ps')." >&2
  exit 1
fi

echo "Creando/actualizando el usuario admin de GVM..."
PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"

if ! docker compose exec -T -u gvmd gvmd gvmd --create-user=admin --password="$PASS" >/dev/null 2>&1; then
  echo "El usuario admin ya existia, reseteo su password..."
  docker compose exec -T -u gvmd gvmd gvmd --user=admin --new-password="$PASS"
fi

ENV_FILE=".env"
touch "$ENV_FILE"
set_env_var() {
  local name="$1" value="$2"
  if grep -q "^${name}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${name}=.*|${name}=${value}|" "$ENV_FILE"
  else
    echo "${name}=${value}" >> "$ENV_FILE"
  fi
}
set_env_var "GVM_USER" "admin"
set_env_var "GVM_PASSWORD" "$PASS"

echo ""
echo "============================================================"
echo " GVM configurado."
echo " Usuario : admin"
echo " Password: $PASS"
echo " (guardadas en .env como GVM_USER / GVM_PASSWORD)"
echo "============================================================"
echo "Ahora completa SCAN_SERVICE_URL y AGENT_API_KEY en .env (ver README.md paso 3)"
echo "y despues: docker compose up -d openvas-agent"
