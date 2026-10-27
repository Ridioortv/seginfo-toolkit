# Restaura un respaldo hecho con respaldar.ps1. REEMPLAZA los datos actuales.
# Uso: powershell -ExecutionPolicy Bypass -File tools\restaurar.ps1 -Archivo C:\respaldos\tero-AAAAMMDD-HHMMSS.dump
param([Parameter(Mandatory=$true)][string]$Archivo, [switch]$Confirmar)
$ErrorActionPreference = "Stop"
$raiz = Split-Path -Parent $PSScriptRoot
Set-Location $raiz
if (-not (Test-Path $Archivo) -or (Get-Item $Archivo).Length -eq 0) { throw "Archivo invalido: $Archivo" }
function Leer($k) {
  $l = Get-Content .env | Where-Object { $_ -match "^$k=" } | Select-Object -Last 1
  if (-not $l) { throw "Falta $k en .env" }
  ($l -replace "^$k=", "").Trim().Trim('"').Trim("'")
}
$u = Leer "POSTGRES_USER"; $db = Leer "POSTGRES_DB"
if (-not $Confirmar) {
  $r = Read-Host "Esto BORRA los datos actuales de '$db' y los reemplaza por $Archivo. Escribi SI para seguir"
  if ($r -cne "SI") { "Cancelado."; exit 1 }
}
docker compose cp $Archivo postgres:/tmp/restore.dump
if ($LASTEXITCODE -ne 0) { throw "No se pudo copiar el archivo al contenedor" }
docker compose exec -T postgres pg_restore -l /tmp/restore.dump | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Archivo invalido (pg_restore -l fallo)" }
$serv = docker compose config --services | Where-Object { $_ -match '-service$|^remote-agent' }
if ($serv) { docker compose stop $serv }
docker compose exec -T postgres pg_restore -U $u -d $db --clean --if-exists --no-owner --single-transaction /tmp/restore.dump
$rc = $LASTEXITCODE
docker compose exec -T postgres rm -f /tmp/restore.dump | Out-Null
docker compose up -d
if ($rc -ne 0) { throw "La restauracion fallo (los datos previos quedaron intactos: es una sola transaccion)" }
"OK: restaurado desde $Archivo. Verifica en la app (Custodia -> Verificar cadena)."
