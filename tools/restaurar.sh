#!/usr/bin/env bash
# Restaura un respaldo hecho con respaldar.sh. REEMPLAZA los datos actuales.
# Uso: ./tools/restaurar.sh ruta/al/tero-AAAAMMDD-HHMMSS.dump
# Recomendado: probarlo cada tanto en una copia de prueba -- un respaldo que nunca
# se restauro no es un respaldo.
set -euo pipefail
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"
ARCH="${1:-}"
[ -n "$ARCH" ] && [ -s "$ARCH" ] || { echo "Uso: $0 archivo.dump" >&2; exit 1; }
[ -f .env ] || { echo "ERROR: no encuentro .env en $RAIZ" >&2; exit 1; }
# Se leen solo estas dos variables (sourcear todo el .env falla con valores con espacios o <>).
leer() { grep -E "^$1=" .env | tail -n1 | cut -d= -f2- | tr -d '\r' | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//'; }
POSTGRES_USER="$(leer POSTGRES_USER)"; POSTGRES_DB="$(leer POSTGRES_DB)"
: "${POSTGRES_USER:?}" "${POSTGRES_DB:?}"
if [ "${CONFIRMAR:-}" != "si" ]; then
  read -r -p "Esto BORRA los datos actuales de '$POSTGRES_DB' y los reemplaza por $ARCH. Escribi SI para seguir: " r
  [ "$r" = "SI" ] || { echo "Cancelado."; exit 1; }
fi
docker compose exec -T postgres pg_restore -l < "$ARCH" > /dev/null || { echo "ERROR: archivo invalido" >&2; exit 1; }
# Los servicios se frenan para que no escriban durante la restauracion.
SERVICIOS="$(docker compose config --services | grep -E -- '-service$|^remote-agent' || true)"
[ -z "$SERVICIOS" ] || docker compose stop $SERVICIOS
docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --single-transaction < "$ARCH"
docker compose up -d
echo "OK: restaurado desde $ARCH. Verifica en la app (Custodia -> Verificar cadena)."
