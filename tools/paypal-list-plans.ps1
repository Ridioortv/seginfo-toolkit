# Lista los planes de suscripcion que hay en tu app de PayPal (solo LEE: no crea ni cobra nada).
# Para cada plan imprime el ID, el nombre, el estado, cuando se creo y el link oficial de
# PayPal para probarlo. El Client ID y el Secret se escriben por consola; no se guardan.
#
# Uso, desde la raiz del repo (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\paypal-list-plans.ps1            # LIVE
#   powershell -ExecutionPolicy Bypass -File tools\paypal-list-plans.ps1 -Sandbox   # pruebas
param([switch]$Sandbox)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
if ($Sandbox) { $base = "https://api-m.sandbox.paypal.com"; $label = "SANDBOX"; $web = "https://www.sandbox.paypal.com" }
else          { $base = "https://api-m.paypal.com";         $label = "LIVE";    $web = "https://www.paypal.com" }

function Fail($m) { Write-Host $m -ForegroundColor Red; exit 1 }
function PayPalError($e) {
    $body = ""
    if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $body = $e.ErrorDetails.Message }
    return "$($e.Exception.Message) $body"
}

Write-Host "Voy a LISTAR los planes de tu app $label de PayPal (solo lectura)." -ForegroundColor Yellow
$clientId = Read-Host "PayPal $label Client ID"
$sec = Read-Host "PayPal $label Secret" -AsSecureString
$secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
try {
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${clientId}:${secret}"))
    $tok = Invoke-RestMethod -Method Post -Uri "$base/v1/oauth2/token" `
        -Headers @{ Authorization = "Basic $basic" } `
        -ContentType "application/x-www-form-urlencoded" -Body "grant_type=client_credentials"
} catch { Fail "PayPal rechazo las credenciales ${label}: $(PayPalError $_)" }
$secret = $null
$H = @{ Authorization = "Bearer $($tok.access_token)" }

try {
    $r = Invoke-RestMethod -Method Get -Uri "$base/v1/billing/plans?page_size=20&total_required=true" -Headers $H
} catch { Fail "No pude listar los planes: $(PayPalError $_)" }

if (-not $r.plans -or $r.plans.Count -eq 0) { Write-Host "No hay planes en esta app." -ForegroundColor Yellow; exit 0 }
Write-Host ""
foreach ($p in $r.plans) {
    Write-Host "------------------------------------------------------------"
    Write-Host "ID:      $($p.id)"
    Write-Host "Nombre:  $($p.name)"
    Write-Host "Estado:  $($p.status)"
    Write-Host "Creado:  $($p.create_time)"
    Write-Host "Probar:  $web/webapps/billing/plans/subscribe?plan_id=$($p.id)"
}
Write-Host "------------------------------------------------------------"
Write-Host "Abri cada link 'Probar' en una ventana privada: el que muestre la pantalla de suscripcion es el plan que sirve." -ForegroundColor Cyan
