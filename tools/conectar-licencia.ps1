# Conecta TU instalacion de TERO Security al servidor de licencias (Render):
#  1) crea tu cliente en el servidor y obtiene su license_key
#  2) escribe LICENSE_SERVER_URL, LICENSE_KEY y LICENSE_SERVER_PUBLIC_KEY en el .env de la app
#  3) comprueba que el servidor responde con la licencia
# El ADMIN_TOKEN se pide por consola (no se guarda en ningun archivo). Lo ves en
# Render -> tu servicio -> Environment -> ADMIN_TOKEN (icono del ojo).
#
# Uso, desde la raiz del repo (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\conectar-licencia.ps1
#   (opcional) -Dias 3650   dias de licencia iniciales (default: 10 anios para tu propia instalacion)
param(
    [string]$ServerUrl = "https://sentinelops-licensing-server.onrender.com",
    [string]$Org = "TERO Security (mi instalacion)",
    [int]$Dias = 3650
)
$ErrorActionPreference = "Stop"
$PublicKey = "B88iF4/B5QWJ+BwVfobj2xcfGBB85Tkt2M4nBh90Ajg="   # publica: solo permite VERIFICAR respuestas
$envPath = Join-Path (Split-Path $PSScriptRoot -Parent) ".env"
if (-not (Test-Path $envPath)) { throw "No encuentro el .env en $envPath" }
$ServerUrl = $ServerUrl.TrimEnd('/')

$sec = Read-Host "ADMIN_TOKEN del servidor de licencias (Render -> Environment)" -AsSecureString
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
if (-not $token) { throw "Hace falta el ADMIN_TOKEN." }

Write-Host "Conectando con $ServerUrl (el plan gratis de Render puede tardar ~1 minuto en despertar)..."
try {
    $r = Invoke-RestMethod -Method Post -Uri "$ServerUrl/admin/clients" -TimeoutSec 120 `
        -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" `
        -Body (@{ org_name = $Org; days = $Dias } | ConvertTo-Json)
} catch {
    throw "No pude crear el cliente: $($_.Exception.Message). Si dice 401, el ADMIN_TOKEN esta mal; si no responde, espera 1 minuto y reintenta."
}
$token = $null
$key = $r.license_key
if (-not $key) { throw "El servidor no devolvio license_key." }

Copy-Item $envPath "$envPath.pre-licencia.bak" -Force
$lines = New-Object System.Collections.Generic.List[string]
foreach ($l in (Get-Content $envPath)) { $lines.Add([string]$l) }
function Set-EnvValue($name, $value) {
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^$name=") { $lines[$i] = "$name=$value"; return }
    }
    $lines.Add("$name=$value")
}
Set-EnvValue "LICENSE_SERVER_URL" $ServerUrl
Set-EnvValue "LICENSE_KEY" $key
Set-EnvValue "LICENSE_SERVER_PUBLIC_KEY" $PublicKey
# UTF-8 SIN BOM: un BOM al inicio rompe la primera variable del env_file de docker compose.
[IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding($false)))

$st = Invoke-RestMethod -Uri "$ServerUrl/license/$key/status" -TimeoutSec 60
Write-Host ""
Write-Host "Listo. Licencia valida: $($st.valid)  hasta: $($st.valid_until)" -ForegroundColor Green
Write-Host "Se guardo en .env (copia anterior: .env.pre-licencia.bak). Ahora reinicia auth-service:"
Write-Host "  docker compose up -d --force-recreate auth-service"
