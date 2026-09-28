# ==========================================================================
# SentinelOps - Agente LAN NATIVO (PowerShell puro).
# NO requiere Python, ni nmap, ni instalar NADA: usa PowerShell + .NET, que
# ya vienen con Windows. Corre en el host (ve la red real), escanea puertos
# de la LAN y reporta a scan-service. Se autentica como el agente "Agente LAN".
# ==========================================================================
$ErrorActionPreference = "Stop"
$scriptDir = $PSScriptRoot
$root      = Split-Path -Parent $scriptDir
$envFile   = Join-Path $root ".env"

$key = $null
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*REMOTE_AGENT_LAN_KEY\s*=\s*(.+?)\s*$') { $key = $Matches[1].Trim() }
    }
}
if ([string]::IsNullOrWhiteSpace($key)) { Write-Error "REMOTE_AGENT_LAN_KEY no esta en .env"; exit 1 }

$scanUrl = if ($env:SCAN_SERVICE_URL) { $env:SCAN_SERVICE_URL.TrimEnd('/') } else { "http://localhost:8003" }
$pollInterval = if ($env:POLL_INTERVAL_SECONDS) { [int]$env:POLL_INTERVAL_SECONDS } else { 10 }
$headers = @{ "X-Agent-Key" = $key }

$ports = @(21,22,23,25,53,80,88,110,111,135,139,143,161,389,443,445,465,587,636,
           993,995,1025,1433,1521,1723,2049,2375,3000,3128,3306,3389,5000,5060,
           5432,5900,5985,6379,8000,8080,8081,8443,8888,9000,9090,9200,10000,27017)
$svcNames = @{ 21="ftp";22="ssh";23="telnet";25="smtp";53="domain";80="http";110="pop3";
  111="rpcbind";135="msrpc";139="netbios-ssn";143="imap";161="snmp";389="ldap";443="https";
  445="microsoft-ds";993="imaps";995="pop3s";1433="ms-sql";3306="mysql";3389="ms-wbt-server";
  5432="postgresql";5900="vnc";6379="redis";8080="http-proxy";8443="https-alt";9200="opensearch";27017="mongodb" }

function Expand-Hosts([string]$target) {
    if ($target -notmatch '/') { return @($target) }
    try {
        $parts  = $target.Split('/')
        $ip     = [System.Net.IPAddress]::Parse($parts[0])
        $prefix = [int]$parts[1]
        $b = $ip.GetAddressBytes(); [Array]::Reverse($b)
        $ipInt = [System.BitConverter]::ToUInt32($b, 0)
        if ($prefix -le 0) { $mask = [uint32]0 } else { $mask = [uint32](([uint32]4294967295) -shl (32 - $prefix)) }
        $net = $ipInt -band $mask
        $count = [int][math]::Pow(2, 32 - $prefix)
        $list = @(); $max = [Math]::Min($count, 258)
        for ($i = 1; $i -lt ($max - 1); $i++) {
            $cur = [uint32]($net + $i)
            $cb = [System.BitConverter]::GetBytes($cur); [Array]::Reverse($cb)
            $list += (New-Object System.Net.IPAddress(,$cb)).ToString()
        }
        if ($list.Count -eq 0) { return @($parts[0]) }
        return $list
    } catch { return @($target) }
}

function Scan-HostPorts([string]$h, [int[]]$portList, [int]$timeoutMs = 800) {
    $clients = @{}; $iars = @{}; $open = @()
    foreach ($p in $portList) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $iars[$p] = $c.BeginConnect($h, $p, $null, $null); $clients[$p] = $c
        } catch { if ($c) { $c.Close() } }
    }
    Start-Sleep -Milliseconds $timeoutMs
    foreach ($p in $portList) {
        $c = $clients[$p]; $iar = $iars[$p]
        if (-not $c) { continue }
        try { if ($iar.IsCompleted) { $c.EndConnect($iar); if ($c.Connected) { $open += $p } } } catch {}
        try { $c.Close() } catch {}
    }
    return $open
}

function Submit-Result([string]$jobId, [string]$status, $findings, [string]$err) {
    $fjson = @()
    foreach ($f in $findings) { $fjson += ($f | ConvertTo-Json -Compress) }
    $arr = "[" + ($fjson -join ",") + "]"
    $body = "{""status"":""$status"",""findings"":$arr,""raw_output"":""agente LAN (PowerShell)"",""error_message"":""$err""}"
    Invoke-RestMethod -Uri "$scanUrl/agents/results/$jobId" -Method Post `
        -Headers @{ "X-Agent-Key" = $key; "Content-Type" = "application/json" } -Body $body -TimeoutSec 30 | Out-Null
}

Write-Host "============================================================"
Write-Host " SentinelOps - Agente LAN (PowerShell nativo) iniciado."
Write-Host " No requiere Python ni nmap. Escanea la red real desde el host."
Write-Host " scan-service: $scanUrl   polling cada ${pollInterval}s   (Ctrl+C para detener)"
Write-Host "============================================================"

while ($true) {
    try {
        $resp = Invoke-RestMethod -Uri "$scanUrl/agents/poll" -Method Post -Headers $headers -TimeoutSec 30
        foreach ($job in @($resp.jobs)) {
            $jobId = $job.id; $target = $job.target; $scanner = $job.scanner_type
            Write-Host "job $($jobId.Substring(0,8)): $scanner -> $target ..."
            if ($scanner -ne "nmap") {
                Submit-Result $jobId "failed" @() "El Agente LAN (PowerShell) solo hace descubrimiento de puertos (nmap). Para $scanner usa el Agente Docker."
                continue
            }
            $hostsList = Expand-Hosts $target
            $findings = @()
            foreach ($h in $hostsList) {
                foreach ($op in (Scan-HostPorts $h $ports)) {
                    $svc = if ($svcNames.ContainsKey($op)) { $svcNames[$op] } else { "" }
                    $findings += @{ title = "Puerto abierto $op/tcp ($svc) en $h"; description = "detectado por el Agente LAN (PowerShell, sin nmap)"; severity = "info"; port = $op; service = $svc }
                }
            }
            Submit-Result $jobId "completed" $findings ""
            Write-Host "job $($jobId.Substring(0,8)): completado, $($findings.Count) hallazgo(s)"
        }
    } catch {
        Write-Host "error hablando con scan-service: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $pollInterval
}
