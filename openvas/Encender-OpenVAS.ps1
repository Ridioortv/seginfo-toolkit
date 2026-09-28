# Enciende el motor OpenVAS/Greenbone (profile "openvas"), que esta apagado
# por defecto. Explica primero POR QUE esta apagado y pide confirmacion.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot   # raiz del repo
Set-Location $root

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " OpenVAS / Greenbone esta APAGADO por defecto" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host " Por que? Es el escaner mas pesado: ~16 contenedores extra que"
Write-Host " descargan varios GB de feeds. Hace que el stack tarde mucho en"
Write-Host " levantar y se rompe seguido en el primer arranque (scap-data)."
Write-Host " Como nmap + nuclei + trivy ya cubren la mayor parte, OpenVAS"
Write-Host " queda apagado para que el programa arranque rapido y estable."
Write-Host ""
Write-Host " Lo vas a prender ahora. La PRIMERA sincronizacion de feeds tarda"
Write-Host " 20-40 min. Despues corre Configurar-OpenVAS.ps1 (ver LEEME.md)."
Write-Host ""
$r = Read-Host " Continuar y encender OpenVAS? (s/N)"
if ($r -notmatch '^[sS]') { Write-Host "Cancelado."; exit 0 }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "No encuentro 'docker'. Abri Docker Desktop y reintenta."; exit 1
}

Write-Host ""
Write-Host "Levantando el profile openvas..." -ForegroundColor Green
docker compose --profile openvas up -d

Write-Host ""
Write-Host "Listo, los contenedores de Greenbone estan arrancando." -ForegroundColor Green
Write-Host "AHORA hay que esperar a que sincronicen los feeds (20-40 min la 1a vez)."
Write-Host "Mira el progreso con:"
Write-Host "    docker compose --profile openvas ps" -ForegroundColor Yellow
Write-Host "Cuando scap-data, gvmd, notus-data y ospd-openvas esten healthy/Up, corre:"
Write-Host "    powershell -ExecutionPolicy Bypass -File openvas\Configurar-OpenVAS.ps1" -ForegroundColor Yellow
Write-Host ""
