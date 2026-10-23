<#
Crea un usuario de prueba con licencia de N dias (por defecto 2 anios = 730).

Crea una ORGANIZACION nueva con su usuario administrador y le suma los dias de suscripcion.
Hace falta una cuenta de administrador de plataforma (la primera cuenta de la instalacion): se pide
por consola y NO se guarda en ningun archivo.

Uso (PowerShell, con TERO Security iniciado):
    powershell -ExecutionPolicy Bypass -File tools\crear-usuario-prueba.ps1 -Email fishela@fishela.com
    (opcional) -Dias 730   -Org "Nombre"   -Nombre "Nombre Apellido"   -Api http://localhost:8001

La contrasena del usuario nuevo necesita al menos 12 caracteres. Si no la pasas con -Password, te la
pide sin mostrarla (mejor: asi no queda en el historial de la terminal).

OJO: si esta instalacion esta conectada a un servidor de licencias (LICENSE_SERVER_URL en .env), el
chequeo periodico (cada 6 h) vuelve a poner el vencimiento de TODAS las organizaciones segun esa
licencia. En ese caso los 2 anios hay que darlos en el servidor (tools\conectar-licencia.ps1 -Dias 730).
#>
param(
    [Parameter(Mandatory = $true)][string]$Email,
    [string]$Password = "",
    [int]$Dias = 730,
    [string]$Org = "",
    [string]$Nombre = "",
    [string]$Api = "http://localhost:8001"
)
$ErrorActionPreference = "Stop"
function Leer-Secreto($pregunta) {
    $sec = Read-Host $pregunta -AsSecureString
    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
if ($Dias -lt 1 -or $Dias -gt 3650) { throw "-Dias tiene que estar entre 1 y 3650." }
if (-not $Password) { $Password = Leer-Secreto "Contrasena para $Email (minimo 12 caracteres)" }
if ($Password.Length -lt 12) { throw "La contrasena necesita al menos 12 caracteres (tiene $($Password.Length))." }
if (-not $Org) { $Org = "Prueba " + $Email.Split("@")[1] }
if (-not $Nombre) { $Nombre = $Email.Split("@")[0] }
$Api = $Api.TrimEnd("/")

$adminEmail = Read-Host "Email del ADMINISTRADOR de la plataforma"
$adminPass = Leer-Secreto "Contrasena de ese administrador"
if (-not $adminEmail -or -not $adminPass) { throw "Hace falta el administrador de la plataforma para crear organizaciones." }

function Llamar($metodo, $ruta, $cuerpo, $token) {
    $h = @{}
    if ($token) { $h["Authorization"] = "Bearer $token" }
    try {
        Invoke-RestMethod -Method $metodo -Uri "$Api$ruta" -Headers $h -ContentType "application/json" -TimeoutSec 30 `
            -Body ($cuerpo | ConvertTo-Json)
    } catch {
        $codigo = [int]$_.Exception.Response.StatusCode
        $detalle = ""
        try { $detalle = ($_.ErrorDetails.Message | ConvertFrom-Json).detail } catch {}
        throw "($codigo) $detalle"
    }
}

try {
    $login = Llamar "POST" "/auth/login" @{ email = $adminEmail; password = $adminPass } $null
} catch {
    throw "El administrador no pudo iniciar sesion $_ -- revisa las credenciales (si tiene MFA, desactivalo un momento) y que TERO Security este iniciado."
}
$adminPass = $null
$token = $login.access_token

try {
    $org = Llamar "POST" "/auth/organizations" @{ name = $Org; admin_email = $Email; admin_password = $Password; admin_full_name = $Nombre } $token
} catch {
    throw "No se pudo crear la organizacion/usuario $_ (403 = esa cuenta no es administrador de la PLATAFORMA; 400 = el email ya esta registrado)."
}
$Password = $null

# Toda organizacion nueva ya arranca con 30 dias: se suma solo la diferencia para que el total sea $Dias.
$vence = $org.organization.subscription_expires_at
if ($Dias -gt 30) {
    try {
        $ext = Llamar "POST" "/auth/organizations/$($org.organization.id)/subscription/extend" @{ days = $Dias - 30 } $token
        $vence = $ext.subscription_expires_at
    } catch {
        throw "La organizacion y el usuario se crearon, pero no pude extender la licencia $_"
    }
}
Write-Host "[OK] Usuario creado: $Email (rol admin de la organizacion `"$Org`")"
Write-Host "[OK] Licencia de $Dias dias, hasta: $vence"
Write-Host "     Si la instalacion usa un servidor de licencias, ese vencimiento lo pisa el chequeo periodico: ver la ayuda del script."
