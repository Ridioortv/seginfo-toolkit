# Configura OpenVAS una vez que los feeds sincronizaron: crea el usuario
# admin de GVM, guarda las credenciales en .env y reinicia scan-service.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$envFile = Join-Path $root ".env"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "No encuentro 'docker'. Abri Docker Desktop y reintenta."; exit 1
}

# Verificar que gvmd este corriendo
$gvmdState = (docker compose ps --format "{{.Service}} {{.State}}" 2>$null | Select-String -Pattern '^gvmd ')
if (-not $gvmdState) {
    Write-Error "gvmd no esta corriendo. Corre primero Encender-OpenVAS.ps1 y espera a que sincronice."
    exit 1
}

Write-Host "Creando/actualizando el usuario admin de GVM..." -ForegroundColor Green
# Password fuerte aleatoria
$chars = (48..57)+(65..90)+(97..122)
$pass = -join ($chars | Get-Random -Count 24 | ForEach-Object {[char]$_})

# Intentar crear; si ya existe, resetear la password
$created = $true
try {
    docker compose exec -T -u gvmd gvmd gvmd --create-user=admin --password=$pass 2>$null
    if ($LASTEXITCODE -ne 0) { $created = $false }
} catch { $created = $false }
if (-not $created) {
    Write-Host "El usuario admin ya existia, reseteo su password..."
    docker compose exec -T -u gvmd gvmd gvmd --user=admin --new-password=$pass
    if ($LASTEXITCODE -ne 0) { Write-Error "No se pudo crear/actualizar el usuario admin de GVM."; exit 1 }
}

# Escribir credenciales en .env (reemplaza si existe, agrega si no)
function Set-EnvVar($name, $value) {
    $lines = @()
    $found = $false
    if (Test-Path $envFile) { $lines = Get-Content $envFile }
    $out = foreach ($l in $lines) {
        if ($l -match "^\s*$name\s*=") { $found = $true; "$name=$value" } else { $l }
    }
    if (-not $found) { $out += "$name=$value" }
    Set-Content -Path $envFile -Value $out -Encoding UTF8
}
Set-EnvVar "GVM_SOCKET_PATH" "/run/gvmd/gvmd.sock"
Set-EnvVar "GVM_USER" "admin"
Set-EnvVar "GVM_PASSWORD" $pass

Write-Host "Reiniciando scan-service para que tome las credenciales..." -ForegroundColor Green
docker compose up -d --no-deps scan-service

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " OpenVAS configurado y conectado a scan-service." -ForegroundColor Cyan
Write-Host " Usuario GVM: admin"
Write-Host " Password   : $pass"
Write-Host " (guardadas en .env como GVM_USER / GVM_PASSWORD)"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Ya podes elegir el scanner 'openvas' en la UI y lanzar." -ForegroundColor Green
Write-Host ""
