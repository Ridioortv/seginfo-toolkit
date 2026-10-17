# Deja PayPal en modo SANDBOX (pruebas, sin dinero real): crea el plan de USD 250 cada 30 dias y el
# webhook en tu app SANDBOX de PayPal, y te imprime PAYPAL_PLAN_ID y PAYPAL_WEBHOOK_ID.
#
# NO cobra nada: solo crea el plan (la definicion del cobro) y el webhook.
# El Client ID y el Secret se escriben por consola; no se guardan en ningun archivo.
#
# Uso, desde la raiz del repo (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\paypal-sandbox.ps1
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
$base = "https://api-m.sandbox.paypal.com"   # SANDBOX (el real es api-m.paypal.com)

function Fail($m) { Write-Host $m -ForegroundColor Red; exit 1 }

function PayPalError($e) {
    $body = ""
    if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $body = $e.ErrorDetails.Message }
    else {
        try {
            $s = $e.Exception.Response.GetResponseStream()
            $body = (New-Object IO.StreamReader($s)).ReadToEnd()
        } catch { }
    }
    return "$($e.Exception.Message) $body"
}

Write-Host "Vas a crear el plan y el webhook en tu app SANDBOX de PayPal (pruebas: no hay dinero real)." -ForegroundColor Yellow

$clientId = Read-Host "PayPal SANDBOX Client ID"
$sec = Read-Host "PayPal SANDBOX Secret" -AsSecureString
$secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))

# ---------- token ----------
try {
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${clientId}:${secret}"))
    $tok = Invoke-RestMethod -Method Post -Uri "$base/v1/oauth2/token" `
        -Headers @{ Authorization = "Basic $basic" } `
        -ContentType "application/x-www-form-urlencoded" -Body "grant_type=client_credentials"
} catch {
    Fail "PayPal rechazo las credenciales SANDBOX: $(PayPalError $_)`nRevisa que sean las de la pestana SANDBOX (no Sandbox)."
}
$secret = $null
$H = @{ Authorization = "Bearer $($tok.access_token)" }
Write-Host "Credenciales SANDBOX correctas." -ForegroundColor Green

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
Write-Host "Plan creado: PAYPAL_PLAN_ID=$($planOut.id)" -ForegroundColor Green

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
    # Si ya habia un webhook con esa URL (o cualquier otro rechazo), se busca y reutiliza el existente.
    try {
        $all = Invoke-RestMethod -Method Get -Uri "$base/v1/notifications/webhooks" -Headers $H
        $webhookId = ($all.webhooks | Where-Object { $_.url -eq $WebhookUrl } | Select-Object -First 1).id
    } catch { }
    if ($webhookId) {
        Write-Host "Ese webhook ya existia en SANDBOX: uso el existente." -ForegroundColor Yellow
    } else {
        Write-Host "PAYPAL_PLAN_ID=$($planOut.id)  (el plan SI se creo; solo fallo el webhook)" -ForegroundColor Yellow
        Fail "No pude crear el webhook: $err"
    }
}
if (-not $webhookId) { Fail "No pude obtener el ID del webhook." }

Write-Host ""
Write-Host "=============== LISTO (SANDBOX) ===============" -ForegroundColor Cyan
Write-Host "PAYPAL_PLAN_ID=$($planOut.id)"
Write-Host "PAYPAL_WEBHOOK_ID=$webhookId"
Write-Host ""
Write-Host "Ahora en Render -> sentinelops-licensing-server -> Environment, cambia estas 5 variables:" -ForegroundColor Cyan
Write-Host "  PAYPAL_ENV            = sandbox"
Write-Host "  PAYPAL_CLIENT_ID      = (el Client ID SANDBOX)"
Write-Host "  PAYPAL_CLIENT_SECRET  = (el Secret SANDBOX)"
Write-Host "  PAYPAL_PLAN_ID        = el de arriba"
Write-Host "  PAYPAL_WEBHOOK_ID     = el de arriba"
Write-Host "y toca 'Save, rebuild, and deploy'."
