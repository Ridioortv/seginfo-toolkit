# Agrega el Agente WAN (internet) al .env y, de paso, REPARA la linea
# BOOTSTRAP_AGENTS si quedo mal formada (por ejemplo con listas anidadas
# [[...],{...}]). Es idempotente: si todo esta bien, no cambia nada.
# Guarda una copia del original en .env.bak antes de escribir.
# No usa ConvertFrom-Json/ConvertTo-Json a proposito: se comportan distinto
# entre Windows PowerShell 5.1 y PowerShell 7 con los arrays.
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
$changed = $false
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
    $changed = $true
}

# 2) BOOTSTRAP_AGENTS: se extraen los pares name/key con una expresion
#    regular (funciona aunque la linea tenga listas anidadas), se sacan
#    duplicados por nombre y se reconstruye una lista plana.
$bootIdx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -like 'BOOTSTRAP_AGENTS=*') { $bootIdx = $i; break }
}
if ($bootIdx -lt 0) { throw "El .env no tiene la linea BOOTSTRAP_AGENTS=..." }
$oldLine = $lines[$bootIdx]
$pairs = [regex]::Matches($oldLine, '"name"\s*:\s*"([^"]*)"\s*,\s*"key"\s*:\s*"([^"]*)"')
$names = New-Object System.Collections.Generic.List[string]
$items = New-Object System.Collections.Generic.List[string]
$hasWan = $false
foreach ($m in $pairs) {
    $n = $m.Groups[1].Value
    $k = $m.Groups[2].Value
    if ($names.Contains($n)) { continue }
    $names.Add($n)
    if ($n -like '*WAN*') { $hasWan = $true }
    $items.Add('{"name":"' + $n + '","key":"' + $k + '"}')
}
if ($items.Count -eq 0) { throw "No pude leer ningun agente de la linea BOOTSTRAP_AGENTS del .env" }
if (-not $hasWan) {
    $items.Add('{"name":"Agente WAN (internet)","key":"' + $key + '"}')
}
$newLine = 'BOOTSTRAP_AGENTS=[' + ($items -join ',') + ']'
if ($newLine -ne $oldLine) {
    $lines[$bootIdx] = $newLine
    $changed = $true
}

if (-not $changed) {
    Write-Host "El Agente WAN ya estaba bien configurado en .env. No se cambio nada."
    exit 0
}

Copy-Item $envPath "$envPath.bak" -Force
# UTF-8 SIN BOM: con BOM, docker compose no lee bien la primera variable.
[System.IO.File]::WriteAllLines($envPath, $lines.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Listo: .env actualizado (copia del original en .env.bak). Agentes en BOOTSTRAP_AGENTS:"
foreach ($n in $names) { Write-Host "  - $n" }
if (-not $hasWan) { Write-Host "  - Agente WAN (internet)" }
Write-Host "Ahora corre:  docker compose up -d --build scan-service remote-agent remote-agent-wan frontend"
