# Agrega el Agente WAN (internet) al .env: la clave REMOTE_AGENT_WAN_KEY y su
# entrada en BOOTSTRAP_AGENTS. Es idempotente: si ya esta, no cambia nada.
# Guarda una copia del original en .env.bak antes de escribir.
#
# Uso, desde la raiz del repo (PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\agregar-agente-wan.ps1
$ErrorActionPreference = "Stop"
$envPath = Join-Path (Split-Path $PSScriptRoot -Parent) ".env"
if (-not (Test-Path $envPath)) { throw "No encuentro el archivo .env en $envPath" }

$lines = New-Object System.Collections.Generic.List[string]
foreach ($l in (Get-Content $envPath)) { $lines.Add([string]$l) }

# 1) Clave del agente WAN (si ya hay una, se reutiliza)
$key = $null
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^REMOTE_AGENT_WAN_KEY=(.+)$') { $key = $Matches[1]; break }
}
$keyAdded = $false
if (-not $key) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $key = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $insertAt = $lines.Count
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -like 'REMOTE_AGENT_LAN_KEY=*') { $insertAt = $i + 1; break }
    }
    $lines.Insert($insertAt, "REMOTE_AGENT_WAN_KEY=$key")
    $keyAdded = $true
}

# 2) Entrada en BOOTSTRAP_AGENTS
$bootIdx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -like 'BOOTSTRAP_AGENTS=*') { $bootIdx = $i; break }
}
if ($bootIdx -lt 0) { throw "El .env no tiene la linea BOOTSTRAP_AGENTS=..." }
$json = $lines[$bootIdx].Substring('BOOTSTRAP_AGENTS='.Length)
$entries = @($json | ConvertFrom-Json)
$bootAdded = $false
$hasWan = $false
foreach ($e in $entries) { if ($e.name -like '*WAN*') { $hasWan = $true } }
if (-not $hasWan) {
    $entries += [pscustomobject]@{ name = 'Agente WAN (internet)'; key = $key }
    $lines[$bootIdx] = 'BOOTSTRAP_AGENTS=' + (ConvertTo-Json -InputObject @($entries) -Compress)
    $bootAdded = $true
}

if (-not $keyAdded -and -not $bootAdded) {
    Write-Host "El Agente WAN ya estaba configurado en .env. No se cambio nada."
    exit 0
}

Copy-Item $envPath "$envPath.bak" -Force
# UTF-8 SIN BOM: con BOM, docker compose no lee bien la primera variable.
[System.IO.File]::WriteAllLines($envPath, $lines.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Listo: Agente WAN agregado al .env (copia del original en .env.bak)."
Write-Host "Ahora corre:  docker compose up -d --build scan-service remote-agent-wan frontend"
