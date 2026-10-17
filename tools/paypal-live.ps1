# Deja PayPal en modo LIVE (produccion): crea el plan de USD 250 cada 30 dias y el
# webhook en tu app LIVE de PayPal, y te imprime PAYPAL_PLAN_ID y PAYPAL_WEBHOOK_ID.
#
# NO cobra nada: solo crea el plan (la definicion del cobro) y el webhook.
# El Client ID y el Secret se escriben por consola; no se guardan en ningun archivo.
#
# Uso, desde la raiz del repo (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\paypal-live.ps1
# Opciones:
#   -WebhookUrl https://sentinelops-licensing-server.onrender.com/webhooks/billing
#   -Price 250 -Days 30
param(
    [string]$WebhookUrl = "https://sentinelops-licensing-server.onrender.com/webhooks/billing",
    [string]$Price = "250",
    [int]$Days = 30
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$base = "https://api-m.paypal.com"   # LIVE (el de pruebas es api-m.sandbox.paypal.com)

function Fail($m) { Write-Host $m -ForegroundColor Red; exit 1 }

function PayPalError($e) {
    $body = ""
    try {
        $s = $e.Exception.Response.GetResponseStream()
        $body = (New-Object IO.StreamReader($s)).ReadToEnd()
    } catch { }
    return "$($e.Exception.Message) $body"
}

Write-Host "Vas a crear el plan y el webhook en tu app LIVE de PayPal (dinero real, aunque este paso no cobra nada)." -ForegroundColor Yellow
$ok = Read-Host "Escribi LIVE para continuar"
if ($ok -ne "LIVE") { Fail "Cancelado." }

$clientId = Read-Host "PayPal LIVE Client ID"
$sec = Read-Host "PayPal LIVE Secret" -AsSecureString
$secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))

# ---------- token ----------
try {
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${clientId}:${secret}"))
    $tok = Invoke-RestMethod -Method Post -Uri "$base/v1/oauth2/token" `
        -Headers @{ Authorization = "Basic $basic" } `
        -ContentType "application/x-www-form-urlencoded" -Body "grant_type=client_credentials"
} catch {
    Fail "PayPal rechazo las credenciales LIVE: $(PayPalError $_)`nRevisa que sean las de la pestana LIVE (no Sandbox)."
}
$secret = $null
$H = @{ Authorization = "Bearer $($tok.access_token)" }
Write-Host "Credenciales LIVE correctas." -ForegroundColor Green

# ---------- producto ----------
try {
    $prod = Invoke-RestMethod -Method Post -Uri "$base/v1/catalogs/products" -Headers $H -ContentType "application/json" `
        -Body (@{ name = "TERO Security"; type = "SERVICE"; category = "SOFTWARE" } | ConvertTo-Json)
} catch { Fail "No pude crear el producto: $(PayPalError $_)" }

# ---------- plan USD 250 cada 30 dias ----------
$plan = @{
    product_id = $prod.id
    name = "TERO Security USD $Price cada $Days dias"
    billing_cycles = @(@{
        frequency = @{ interval_unit = "DAY"; interval_count = $Days }
        tenure_type = "REGULAR"
        sequence = 1
        total_cycles = 0
        pricing_scheme = @{ fixed_price = @{ value = $Price; currency_code = "USD" } }
    })
    payment_preferences = @{ auto_bill_outstanding = $true; payment_failure_threshold = 3 }
}
try {
    $planOut = Invoke-RestMethod -Method Post -Uri "$base/v1/billing/plans" -Headers $H -ContentType "application/json" `
        -Body ($plan | ConvertTo-Json -Depth 8)
} catch { Fail "No pude crear el plan: $(PayPalError $_)" }

# ---------- webhook ----------
$webhookId = $null
$hook = @{
    url = $WebhookUrl
    event_types = @(@{ name = "BILLING.SUBSCRIPTION.ACTIVATED" }, @{ name = "PAYMENT.SALE.COMPLETED" })
}
try {
    $w = Invoke-RestMethod -Method Post -Uri "$base/v1/notifications/webhooks" -Headers $H -ContentType "application/json" `
        -Body ($hook | ConvertTo-Json -Depth 6)
    $webhookId = $w.id
} catch {
    $err = PayPalError $_
    if ($err -match "WEBHOOK_URL_ALREADY_EXISTS") {
        $all = Invoke-RestMethod -Method Get -Uri "$base/v1/notifications/webhooks" -Headers $H
        $webhookId = ($all.webhooks | Where-Object { $_.url -eq $WebhookUrl } | Select-Object -First 1).id
        Write-Host "Ese webhook ya existia en LIVE: uso el existente." -ForegroundColor Yellow
    } else {
        Fail "No pude crear el webhook: $err"
    }
}
if (-not $webhookId) { Fail "No pude obtener el ID del webhook." }

Write-Host ""
Write-Host "=============== LISTO (LIVE) ===============" -ForegroundColor Cyan
Write-Host "PAYPAL_PLAN_ID=$($planOut.id)"
Write-Host "PAYPAL_WEBHOOK_ID=$webhookId"
Write-Host ""
Write-Host "Ahora en Render -> sentinelops-licensing-server -> Environment, cambia estas 5 variables:" -ForegroundColor Cyan
Write-Host "  PAYPAL_ENV            = live"
Write-Host "  PAYPAL_CLIENT_ID      = (el Client ID LIVE)"
Write-Host "  PAYPAL_CLIENT_SECRET  = (el Secret LIVE)"
Write-Host "  PAYPAL_PLAN_ID        = el de arriba"
Write-Host "  PAYPAL_WEBHOOK_ID     = el de arriba"
Write-Host "y toca 'Save, rebuild, and deploy'."
