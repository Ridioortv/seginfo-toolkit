# Configura el correo de TERO Security para "Olvide mi contrasena" (y para el canal de
# notificaciones por email). Por defecto usa una cuenta de Gmail con CLAVE DE APLICACION.
#  1) pide la clave de aplicacion por consola (no se muestra ni se guarda en ningun otro lado)
#  2) manda un mail de prueba a la propia cuenta: si falla, NO toca el .env
#  3) escribe SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD y SMTP_FROM en el .env de la app
#  4) reinicia auth-service para que tome los valores nuevos
#
# La clave de aplicacion se crea en https://myaccount.google.com/apppasswords
# (la cuenta tiene que tener la verificacion en 2 pasos activada). Son 16 letras.
#
# Uso, desde la raiz del repo (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\configurar-correo.ps1
#   (opcional) -Usuario otra@cuenta.com   -Desde soporte@tuempresa.com   -SinReiniciar
# Nota: Gmail reemplaza el remitente por la cuenta autenticada, salvo que ese "Desde" este dado
# de alta en Gmail > Configuracion > Cuentas > "Enviar como".
param(
    [string]$SmtpHost = "smtp.gmail.com",
    [int]$Puerto = 587,
    [string]$Usuario = "tecnoros@gmail.com",
    [string]$Desde = "",
    [switch]$SinReiniciar
)
$ErrorActionPreference = "Stop"
$raiz = Split-Path $PSScriptRoot -Parent
$envPath = Join-Path $raiz ".env"
if (-not (Test-Path $envPath)) { throw "No encuentro el .env en $envPath (corre primero TERO Security - Iniciar.exe)." }

$u = Read-Host "Cuenta que envia los mails [$Usuario]"
if ($u) { $Usuario = $u.Trim() }
if (-not $Desde) { $Desde = $Usuario }

$sec = Read-Host "Clave de aplicacion de $Usuario (16 letras, se ocultan al escribir)" -AsSecureString
$clave = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
$clave = ($clave -replace "\s", "")
if (-not $clave) { throw "Hace falta la clave de aplicacion." }

Write-Host "Probando el envio con $SmtpHost`:$Puerto (te llega un mail de prueba a $Usuario)..."
try {
    $smtp = New-Object Net.Mail.SmtpClient($SmtpHost, $Puerto)
    $smtp.EnableSsl = $true
    $smtp.Timeout = 30000
    $smtp.Credentials = New-Object Net.NetworkCredential($Usuario, $clave)
    $msg = New-Object Net.Mail.MailMessage($Desde, $Usuario, "TERO Security: prueba de correo",
        "Si lees esto, el correo de TERO Security quedo bien configurado.")
    $smtp.Send($msg)
} catch {
    $clave = $null
    throw "No pude enviar el mail de prueba: $($_.Exception.Message). Si dice 535 o 'Authentication', la clave de aplicacion esta mal (o falta la verificacion en 2 pasos); si dice timeout, un firewall o antivirus bloquea el puerto $Puerto. El .env NO se modifico."
}

Copy-Item $envPath "$envPath.pre-correo.bak" -Force
$lines = New-Object System.Collections.Generic.List[string]
foreach ($l in (Get-Content $envPath)) { $lines.Add([string]$l) }
function Set-EnvValue($name, $value) {
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^$name=") { $lines[$i] = "$name=$value"; return }
    }
    $lines.Add("$name=$value")
}
Set-EnvValue "SMTP_HOST" $SmtpHost
Set-EnvValue "SMTP_PORT" "$Puerto"
Set-EnvValue "SMTP_USER" $Usuario
Set-EnvValue "SMTP_PASSWORD" $clave
Set-EnvValue "SMTP_FROM" $Desde
# UTF-8 SIN BOM: un BOM al inicio rompe la primera variable del env_file de docker compose.
[IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
$clave = $null

Write-Host "Mail de prueba enviado y datos guardados en .env (copia anterior: .env.pre-correo.bak)." -ForegroundColor Green
if ($SinReiniciar) {
    Write-Host "Falta reiniciar auth-service:  docker compose up -d --force-recreate auth-service"
    return
}
Push-Location $raiz
try {
    # Los lanzadores fijan TERO_VERSION desde VERSION; sin eso compose usa imagenes ':local' que no existen.
    $env:TERO_VERSION = (Get-Content (Join-Path $raiz "VERSION") -Raw).Trim()
    docker compose up -d --force-recreate auth-service
} finally { Pop-Location }
Write-Host ""
Write-Host "Listo. Proba en la pantalla de entrada: 'Olvidaste tu contrasena?' con un usuario que tenga contrasena." -ForegroundColor Green
Write-Host "El link llega por mail, vale 30 minutos y se usa una sola vez."
