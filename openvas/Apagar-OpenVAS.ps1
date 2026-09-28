# Apaga los contenedores de OpenVAS/Greenbone (no borra los feeds).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$gvm = @("ospd-openvas","openvasd","openvas","configure-openvas","gvmd","pg-gvm-migrator",
         "pg-gvm","gvm-redis","report-formats","data-objects","dfn-cert-data","cert-bund-data",
         "scap-data","notus-data","vulnerability-tests","gpg-data")

Write-Host "Deteniendo los contenedores de OpenVAS/Greenbone..." -ForegroundColor Green
docker compose stop $gvm
Write-Host ""
Write-Host "OpenVAS apagado. El resto del programa sigue funcionando normal." -ForegroundColor Green
Write-Host "Para prenderlo de nuevo: openvas\Encender-OpenVAS.ps1" -ForegroundColor Yellow
