#!/usr/bin/env bash
# Respaldo de la base de datos de TERO (Postgres) -> archivo comprimido con fecha.
# Uso:   ./tools/respaldar.sh [carpeta_destino]      (por defecto ./backups)
# Cron:  0 3 * * *  cd /ruta/a/tero && ./tools/respaldar.sh /ruta/respaldos
# Lee POSTGRES_USER / POSTGRES_DB del .env (no los muestra ni los copia).
# IMPORTANTE: guarda aparte (en un lugar seguro, FUERA del servidor) el archivo .env:
# contiene CUSTODY_SIGNING_SEED y ENCRYPTION_KEY; sin ellos un respaldo de la base
# no permite verificar la cadena de custodia ni descifrar credenciales guardadas.
set -euo pipefail
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"
DEST="${1:-$RAIZ/backups}"
RETENCION_DIAS="${RETENCION_DIAS:-14}"
[ -f .env ] || { echo "ERROR: no encuentro .env en $RAIZ" >&2; exit 1; }
# Se leen solo estas dos variables (sourcear todo el .env falla con valores con espacios o <>).
leer() { grep -E "^$1=" .env | tail -n1 | cut -d= -f2- | tr -d '\r' | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//'; }
POSTGRES_USER="$(leer POSTGRES_USER)"; POSTGRES_DB="$(leer POSTGRES_DB)"
: "${POSTGRES_USER:?falta POSTGRES_USER en .env}" "${POSTGRES_DB:?falta POSTGRES_DB en .env}"
mkdir -p "$DEST"; chmod 700 "$DEST"
ARCH="$DEST/tero-$(date +%Y%m%d-%H%M%S).dump"
TMP="$ARCH.parcial"
trap 'rm -f "$TMP"' EXIT
# -Fc = formato comprimido de pg_dump (permite restaurar tabla por tabla).
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner > "$TMP"
# Un respaldo vacio o ilegible no cuenta: se valida antes de guardarlo.
[ -s "$TMP" ] || { echo "ERROR: el respaldo salio vacio" >&2; exit 1; }
docker compose exec -T postgres pg_restore -l < "$TMP" > /dev/null \
  || { echo "ERROR: el respaldo no se puede leer (pg_restore -l fallo)" >&2; exit 1; }
mv "$TMP" "$ARCH"; trap - EXIT
chmod 600 "$ARCH"
# Rotacion: borra respaldos de TERO mas viejos que RETENCION_DIAS.
find "$DEST" -maxdepth 1 -name 'tero-*.dump' -mtime +"$RETENCION_DIAS" -delete
echo "OK: $ARCH ($(du -h "$ARCH" | cut -f1))"
