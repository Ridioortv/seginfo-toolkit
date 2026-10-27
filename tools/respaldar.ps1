# Respaldo de la base de datos de TERO (Postgres) en Windows.
# Uso:  powershell -ExecutionPolicy Bypass -File tools\respaldar.ps1 [-Destino C:\respaldos]
# Programarlo a diario: Programador de tareas de Windows -> ejecutar este comando.
# IMPORTANTE: guarda aparte (fuera del servidor) el archivo .env: tiene CUSTODY_SIGNING_SEED
# y ENCRYPTION_KEY; sin ellos un respaldo de la base no sirve para verificar la cadena de
# custodia ni descifrar credenciales guardadas.
param([string]$Destino = "", [int]$RetencionDias = 14)
$ErrorActionPreference = "Stop"
$raiz = Split-Path -Parent $PSScriptRoot
Set-Location $raiz
if (-not (Test-Path .env)) { throw "No encuentro .env en $raiz" }
function Leer($k) {
  $l = Get-Content .env | Where-Object { $_ -match "^$k=" } | Select-Object -Last 1
  if (-not $l) { throw "Falta $k en .env" }
  ($l -replace "^$k=", "").Trim().Trim('"').Trim("'")
}
$u = Leer "POSTGRES_USER"; $db = Leer "POSTGRES_DB"
if (-not $Destino) { $Destino = Join-Path $raiz "backups" }
New-Item -ItemType Directory -Force -Path $Destino | Out-Null
$arch = Join-Path $Destino ("tero-{0}.dump" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
# El dump se hace DENTRO del contenedor y se copia como archivo (sin pasar por la consola,
# que corrompe datos binarios).
docker compose exec -T postgres pg_dump -U $u -d $db -Fc --no-owner -f /tmp/tero.dump
if ($LASTEXITCODE -ne 0) { throw "pg_dump fallo" }
docker compose cp postgres:/tmp/tero.dump "$arch.parcial"
if ($LASTEXITCODE -ne 0) { throw "No se pudo copiar el respaldo" }
docker compose exec -T postgres pg_restore -l /tmp/tero.dump | Out-Null
$ok = $LASTEXITCODE -eq 0
docker compose exec -T postgres rm -f /tmp/tero.dump | Out-Null
if (-not $ok -or (Get-Item "$arch.parcial").Length -eq 0) { Remove-Item "$arch.parcial" -Force; throw "El respaldo salio vacio o ilegible" }
Move-Item "$arch.parcial" $arch
Get-ChildItem $Destino -Filter "tero-*.dump" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$RetencionDias) } | Remove-Item -Force
"OK: $arch ({0:N1} KB)" -f ((Get-Item $arch).Length / 1KB)
