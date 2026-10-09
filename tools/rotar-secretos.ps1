<#
.SYNOPSIS
  Rota los secretos locales de SentinelOps (.env) por valores aleatorios fuertes.

.DESCRIPTION
  Reemplaza en .env: JWT_SECRET_KEY, ENCRYPTION_KEY, POSTGRES_PASSWORD y las
  claves de los agentes (REMOTE_AGENT_*_KEY + BOOTSTRAP_AGENTS). NUNCA imprime
  los valores. Hace backup previo de .env (ignorado por git) y cambia la
  contrasena dentro de Postgres ANTES de tocar el archivo, asi si algo falla
  el .env queda intacto.

  Efectos a tener en cuenta:
   - Se cierran todas las sesiones (cambia el secreto JWT): hay que volver a entrar.
   - ENCRYPTION_KEY nueva: si ya cargaste secretos de SSO o conectores de
     integracion, hay que volver a cargarlos (estaban cifrados con la clave vieja).
   - Los agentes se re-registran solos con las claves nuevas; el Agente LAN
     (PowerShell en tu PC) se reinicia para leer la clave nueva.

.PARAMETER SoloArchivo
  Solo reescribe .env (sin tocar Postgres ni Docker). Util para instalaciones nuevas
  donde todavia no existe el volumen de la base.

.PARAMETER SinAgentes
  No rota las claves de los agentes.

.PARAMETER Si
  No pide confirmacion.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\rotar-secretos.ps1
#>
[CmdletBinding()]
param(
    [switch]$SoloArchivo,
    [switch]$SinAgentes,
    [switch]$Si
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$envPath = Join-Path $root '.env'
if (-not (Test-Path -LiteralPath $envPath)) { throw ".env no existe en $root. Copia .env.example a .env primero." }

function New-HexSecret([int]$Bytes) {
    $b = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

$raw = [System.IO.File]::ReadAllText($envPath)
$nl = if ($raw.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = New-Object System.Collections.Generic.List[string]
foreach ($l in ($raw -split "`r?`n")) { $lines.Add($l) }
# ReadAllText + split deja una linea vacia final si el archivo termina en salto de linea.

function Get-EnvValue([string]$Key) {
    foreach ($l in $lines) { if ($l -match "^\s*$([regex]::Escape($Key))\s*=(.*)$") { return $Matches[1].Trim() } }
    return $null
}
function Set-EnvValue([string]$Key, [string]$Value) {
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s*$([regex]::Escape($Key))\s*=") { $lines[$i] = "$Key=$Value"; return }
    }
    # No existia: se inserta antes de la linea vacia final (si la hay).
    $at = $lines.Count
    if ($at -gt 0 -and [string]::IsNullOrEmpty($lines[$at - 1])) { $at-- }
    $lines.Insert($at, "$Key=$Value")
}
function Test-Weak($v) {
    return ([string]::IsNullOrWhiteSpace($v) -or $v.Length -lt 24 -or $v -match 'changeme|cambiame|dev-secret|dev-encryption|example|password')
}

$pgUser = Get-EnvValue 'POSTGRES_USER'; if (-not $pgUser) { $pgUser = 'sentinelops' }

Write-Host ""
Write-Host "Estado actual de los secretos (sin mostrar valores):" -ForegroundColor Cyan
foreach ($k in 'JWT_SECRET_KEY','ENCRYPTION_KEY','POSTGRES_PASSWORD','REMOTE_AGENT_DOCKER_KEY','REMOTE_AGENT_LAN_KEY','REMOTE_AGENT_WAN_KEY') {
    $v = Get-EnvValue $k
    $estado = if ($null -eq $v) { 'FALTA' } elseif (Test-Weak $v) { 'DEBIL / ejemplo' } else { 'ok (se rota igual)' }
    Write-Host ("  {0,-26} {1}" -f $k, $estado)
}
Write-Host ""
if (-not $Si) {
    $r = Read-Host "Se cerraran todas las sesiones y se reiniciara el stack. Escribi SI para continuar"
    if ($r -ne 'SI') { Write-Host "Cancelado. No se toco nada."; exit 0 }
}

# Valores nuevos (hex: sin caracteres que haya que escapar en URLs de conexion).
$new = @{
    JWT_SECRET_KEY    = New-HexSecret 48
    ENCRYPTION_KEY    = New-HexSecret 48
    POSTGRES_PASSWORD = New-HexSecret 24
}
if (-not $SinAgentes) {
    $new['REMOTE_AGENT_DOCKER_KEY'] = New-HexSecret 32
    $new['REMOTE_AGENT_LAN_KEY']    = New-HexSecret 32
    $new['REMOTE_AGENT_WAN_KEY']    = New-HexSecret 32
}

# 1) Backup (git lo ignora: *.bak). Borralo cuando confirmes que todo anda.
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = "$envPath.pre-rotacion-$stamp.bak"
Copy-Item -LiteralPath $envPath -Destination $backup
Write-Host "Backup: $(Split-Path -Leaf $backup)  (borralo cuando todo funcione: contiene los secretos viejos)" -ForegroundColor DarkGray

# 2) Contrasena de Postgres DENTRO de la base, antes de tocar .env.
if (-not $SoloArchivo) {
    docker compose version *> $null
    if ($LASTEXITCODE -ne 0) { throw "Docker no responde. Inicia Docker Desktop o usa -SoloArchivo." }
    $running = docker compose ps --status running -q postgres
    if (-not $running) {
        Write-Host "Levantando postgres..." -ForegroundColor Cyan
        docker compose up -d postgres | Out-Null
    }
    $ok = $false
    for ($i = 0; $i -lt 60; $i++) {
        docker compose exec -T postgres pg_isready -U $pgUser *> $null
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ok) { throw "Postgres no quedo listo. .env NO fue modificado." }
    $sql = "ALTER USER `"$pgUser`" WITH PASSWORD '$($new['POSTGRES_PASSWORD'])';"
    $out = $sql | docker compose exec -T postgres psql -U $pgUser -d postgres -v ON_ERROR_STOP=1 2>&1
    if ($LASTEXITCODE -ne 0) { throw "No se pudo cambiar la contrasena en Postgres. .env NO fue modificado. Detalle: $out" }
    Write-Host "Contrasena de Postgres actualizada dentro de la base." -ForegroundColor Green
}

# 3) Reescribir .env.
foreach ($k in $new.Keys) { Set-EnvValue $k $new[$k] }

if (-not $SinAgentes) {
    # BOOTSTRAP_AGENTS: mismas claves nuevas (por nombre de agente); los agentes
    # que no reconozco se dejan como estan.
    $json = Get-EnvValue 'BOOTSTRAP_AGENTS'
    if ($json) {
        try {
            $agents = @($json | ConvertFrom-Json)
            foreach ($a in $agents) {
                if ($a.name -match 'Docker') { $a.key = $new['REMOTE_AGENT_DOCKER_KEY'] }
                elseif ($a.name -match 'LAN') { $a.key = $new['REMOTE_AGENT_LAN_KEY'] }
                elseif ($a.name -match 'WAN') { $a.key = $new['REMOTE_AGENT_WAN_KEY'] }
            }
            $newJson = ConvertTo-Json -InputObject $agents -Compress
            Set-EnvValue 'BOOTSTRAP_AGENTS' $newJson
        } catch {
            Write-Warning "No pude interpretar BOOTSTRAP_AGENTS ($($_.Exception.Message)). Actualizalo a mano con las claves nuevas."
        }
    }
}

$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($envPath, ($lines -join $nl), $enc)
Write-Host ".env actualizado con secretos nuevos." -ForegroundColor Green

if ($SoloArchivo) {
    Write-Host "Listo (solo archivo). Si el stack ya existia, falta cambiar la contrasena en Postgres y reiniciar." -ForegroundColor Yellow
    exit 0
}

# 4) Reiniciar el stack para que todos los servicios lean los valores nuevos.
Write-Host "Reiniciando el stack (docker compose up -d --build --force-recreate)..." -ForegroundColor Cyan
docker compose up -d --build --force-recreate
if ($LASTEXITCODE -ne 0) { Write-Warning "docker compose devolvio un error; revisa 'docker compose ps' y 'docker compose logs --tail=40'." }

Write-Host ""
Write-Host "Listo. Pendiente de tu lado:" -ForegroundColor Cyan
Write-Host "  1) Volve a iniciar sesion en la app (las sesiones anteriores quedaron invalidas)."
Write-Host "  2) Si usas el Agente LAN en tu PC, reinicialo: lee la clave nueva de .env al arrancar."
Write-Host "  3) Si habias configurado SSO o conectores de integracion, volve a cargar sus secretos."
Write-Host "  4) Cuando todo funcione, borra el backup .env.pre-rotacion-*.bak."
