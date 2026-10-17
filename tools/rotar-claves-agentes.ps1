# Cambia SOLO las 3 claves de los agentes de escaneo remoto en .env
# (REMOTE_AGENT_DOCKER_KEY / _LAN_KEY / _WAN_KEY) y las mismas claves dentro de BOOTSTRAP_AGENTS.
# No toca JWT, ENCRYPTION_KEY, Postgres, Redis ni nada mas.
# Uso (desde la raiz del repo):  .\rotar-claves-agentes.ps1
$ErrorActionPreference = "Stop"
$envPath = Join-Path (Get-Location) ".env"
if (-not (Test-Path $envPath)) { throw "No encuentro .env en $(Get-Location). Corre esto desde la raiz del repo." }

function New-Key {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

$lines = [System.IO.File]::ReadAllLines($envPath)
$names = @("REMOTE_AGENT_DOCKER_KEY", "REMOTE_AGENT_LAN_KEY", "REMOTE_AGENT_WAN_KEY")
foreach ($name in $names) {
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].StartsWith($name + "=")) { $idx = $i; break } }
    if ($idx -lt 0) { Write-Host "AVISO: no encontre $name en .env, lo salteo."; continue }
    $old = $lines[$idx].Substring($name.Length + 1).Trim()
    $new = New-Key
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($old.Length -gt 0) { $lines[$i] = $lines[$i].Replace($old, $new) }
    }
    Write-Host "OK: $name rotada."
}
[System.IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding $false))
Write-Host ""
Write-Host "Listo. Ahora: docker compose up -d --force-recreate scan-service remote-agent"
Write-Host "Si usas el agente LAN/WAN en otra PC, reinicialo (toma la clave nueva del .env)."
