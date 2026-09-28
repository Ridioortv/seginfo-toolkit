# ==========================================================================
# SentinelOps - Agente LAN NATIVO (PowerShell puro).
# NO requiere Python, ni nmap, ni instalar NADA: usa PowerShell + .NET, que
# ya vienen con Windows. Corre en el host (ve la red real), escanea puertos
# de la LAN y reporta a scan-service. Se autentica como el agente "Agente LAN".
#
# Uso:
#   .\agente-lan.ps1            arranca el agente en primer plano (Ctrl+C
#                                para detener) -- para probarlo una vez o
#                                ver en vivo que esta haciendo.
#   .\agente-lan.ps1 -Install   lo deja instalado para que arranque SOLO
#                                cada vez que inicies sesion en Windows, sin
#                                tener que abrir nada de nuevo -- no hace
#                                falta ser administrador. Tambien lo arranca
#                                ya mismo, sin esperar al proximo login.
#   .\agente-lan.ps1 -Status    muestra si esta instalado, corriendo, y las
#                                ultimas lineas de su log.
#   .\agente-lan.ps1 -Uninstall lo saca de los programas de inicio (no borra
#                                este archivo, solo deja de arrancar solo).
# ==========================================================================
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status
)

$ErrorActionPreference = "Stop"
$scriptDir  = $PSScriptRoot
$scriptPath = Join-Path $scriptDir "agente-lan.ps1"
$root       = Split-Path -Parent $scriptDir
$envFile    = Join-Path $root ".env"
$logPath    = Join-Path $scriptDir "agente-lan.log"
$TaskName   = "SentinelOps Agente LAN"

function Write-Log([string]$msg) {
    # Escribe en pantalla (si hay consola visible, ej. corriendo a mano) Y
    # en un archivo de log (para cuando corre instalado, en segundo plano,
    # sin ventana) -- asi hay donde mirar si algo no anda sin tener que
    # dejar el agente corriendo en primer plano todo el tiempo.
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    Write-Host $line
    try { Add-Content -Path $logPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

# --------------------------------------------------------------------------
# Instalacion como tarea de Windows -- para que "trabaje automaticamente":
# se registra para arrancar solo al iniciar sesion, no necesita quedar una
# ventana abierta, y si Windows lo reinicia (o se cae por un error) vuelve a
# arrancar solo. Usa el modulo ScheduledTasks que ya viene con Windows 10/11
# -- no instala nada nuevo, y no pide ser administrador (se registra para
# tu propio usuario, con permisos normales).
# --------------------------------------------------------------------------
function Install-AgentTask {
    $psExe = (Get-Process -Id $PID).Path
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Ya estaba instalado -- lo vuelvo a registrar por si cambio la ruta o el usuario."
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    $action = New-ScheduledTaskAction -Execute $psExe `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings `
        -Description "SentinelOps: agente LAN, escanea la red real (192.168.x.x, etc.) desde este host. Instalado por agente-lan.ps1 -Install." `
        -Force | Out-Null

    Write-Host "Instalado: el Agente LAN va a arrancar solo cada vez que inicies sesion en Windows."
    Write-Host "Arrancandolo ahora tambien, para no tener que cerrar sesion y volver a entrar..."
    try {
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep -Seconds 2
        Write-Host "Listo. Revisa la tabla de agentes en SentinelOps (pestana Escaneos) -- 'Agente LAN' deberia mostrar 'Ultima vez visto' con la hora de ahora en unos segundos."
        Write-Host "Log en: $logPath"
    } catch {
        Write-Host "Se instalo, pero no pude arrancarlo ya mismo ($($_.Exception.Message)). Va a arrancar solo la proxima vez que inicies sesion."
    }
}

function Uninstall-AgentTask {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Host "No estaba instalado como tarea de inicio (nada para sacar)."
        return
    }
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Desinstalado: el Agente LAN ya no arranca solo con Windows."
    Write-Host "Si tenia una instancia corriendo, puede tardar unos segundos en detenerse."
}

function Show-AgentStatus {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host "No esta instalado. Corre: .\agente-lan.ps1 -Install"
        return
    }
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Host "Instalado. Estado de la tarea: $($task.State)"
    Write-Host "Ultima corrida: $($info.LastRunTime)   Resultado: $($info.LastTaskResult) (0 = OK)"
    Write-Host "Proxima corrida programada (proximo login): $($info.NextRunTime)"
    if (Test-Path $logPath) {
        Write-Host "--- Ultimas lineas del log ($logPath) ---"
        Get-Content $logPath -Tail 10
    } else {
        Write-Host "Todavia no genero log -- puede que no haya arrancado todavia."
    }
}

if ($Install)   { Install-AgentTask; exit 0 }
if ($Uninstall) { Uninstall-AgentTask; exit 0 }
if ($Status)    { Show-AgentStatus; exit 0 }

# --------------------------------------------------------------------------
# A partir de aca: el agente en si (igual que antes), corra instalado como
# tarea (en segundo plano, sin ventana) o a mano con Iniciar-Agente-LAN.bat.
# --------------------------------------------------------------------------
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

# --------------------------------------------------------------------------
# nuclei/trivy: si estan instalados en ESTA PC (basta con que
# `nuclei`/`trivy` respondan desde una consola cualquiera, no hace falta
# nada mas), este agente los usa de verdad -- mismos flags/restricciones
# que el driver in-container (app/scanners/nuclei.py, app/scanners/
# trivy.py) y que remote-agent/agent.py, para mantener la misma postura
# de seguridad (solo deteccion, nunca explotacion activa). Se chequea en
# CADA job, no solo al arrancar, para que instalarlos mientras el agente
# ya esta corriendo funcione sin tener que reiniciarlo. Si no estan, el
# job vuelve con un mensaje claro en vez de intentarlo (openvas sigue sin
# soporte aca: necesita el motor completo de Greenbone, no un binario
# suelto).
# --------------------------------------------------------------------------
$NucleiSeverityMap = @{ critical="critical"; high="high"; medium="medium"; low="low"; info="info"; unknown="info" }
$TrivySeverityMap  = @{ CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; UNKNOWN="info" }

function Invoke-ScannerBinary([string]$exe, [string[]]$scannerArgs, [int]$timeoutSeconds) {
    # Corre un binario externo (nuclei/trivy) con limite de tiempo real --
    # equivalente a subprocess.run(..., timeout=N) de Python: si se pasa
    # el timeout, lo mata y devuelve TimedOut=true en vez de colgar el
    # loop de polling para siempre.
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        foreach ($a in $scannerArgs) { $psi.ArgumentList.Add($a) }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        $exited = $proc.WaitForExit($timeoutSeconds * 1000)
        if (-not $exited) {
            try { $proc.Kill() } catch {}
            return @{ TimedOut = $true; Stdout = ""; Stderr = ""; ExitCode = -1 }
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        return @{ TimedOut = $false; Stdout = $stdout; Stderr = $stderr; ExitCode = $proc.ExitCode }
    } catch {
        return @{ TimedOut = $false; Stdout = ""; Stderr = $_.Exception.Message; ExitCode = -1 }
    }
}

function Get-NucleiFindings([string]$rawJsonl) {
    $findings = @()
    foreach ($line in ($rawJsonl -split "`n")) {
        $line = $line.Trim()
        if (-not $line) { continue }
        try { $ev = $line | ConvertFrom-Json } catch { continue }
        $info = $ev.info
        $sev = "info"
        if ($info -and $info.severity -and $NucleiSeverityMap.ContainsKey([string]$info.severity)) { $sev = $NucleiSeverityMap[[string]$info.severity] }
        $cve = $null
        if ($info -and $info.classification -and $info.classification.'cve-id') {
            $cveList = @($info.classification.'cve-id')
            if ($cveList.Count -gt 0) { $cve = $cveList[0] }
        }
        $title = "hallazgo nuclei"
        if ($info -and $info.name) { $title = $info.name } elseif ($ev.'template-id') { $title = $ev.'template-id' }
        $desc = ""
        if ($info -and $info.description) { $desc = [string]$info.description; $desc = $desc.Substring(0, [Math]::Min(1000, $desc.Length)) }
        $findings += @{ title = $title; description = $desc; severity = $sev; cve_id = $cve; service = $ev.'matched-at' }
    }
    return $findings
}

function Invoke-NucleiScan([string]$target, $options) {
    $scannerArgs = @("-target", $target, "-etags", "dos,fuzz,intrusive", "-jsonl", "-silent", "-no-interactsh", "-timeout", "10", "-duc")
    $tags = $null
    if ($options -and $options.tags) { $tags = [string]$options.tags }
    if ($tags) {
        $safeTags = @()
        foreach ($t in ($tags -split ",")) {
            $tt = $t.Trim()
            if ($tt -and ($tt -match '^[a-zA-Z0-9]+$')) { $safeTags += $tt }
        }
        if ($safeTags.Count -gt 0) { $scannerArgs += @("-tags", ($safeTags -join ",")) }
    }
    $nucleiCmd = Get-Command nuclei -ErrorAction SilentlyContinue
    $result = Invoke-ScannerBinary -exe $nucleiCmd.Source -scannerArgs $scannerArgs -timeoutSeconds 600
    if ($result.TimedOut) { return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (600s) contra $target" } }
    if (($result.ExitCode -ne 0) -and ($result.ExitCode -ne 1) -and (-not $result.Stdout.Trim())) {
        $errMsg = $result.Stderr; $errMsg = $errMsg.Substring(0, [Math]::Min(2000, $errMsg.Length))
        return @{ Raw = $result.Stdout; Findings = @(); Error = $errMsg }
    }
    return @{ Raw = $result.Stdout; Findings = (Get-NucleiFindings $result.Stdout); Error = "" }
}

function Get-TrivyFindings([string]$rawJson) {
    $findings = @()
    if (-not $rawJson.Trim()) { return $findings }
    try { $payload = $rawJson | ConvertFrom-Json } catch { return $findings }
    foreach ($result in @($payload.Results)) {
        if (-not $result) { continue }
        $targetName = $result.Target
        foreach ($vuln in @($result.Vulnerabilities)) {
            if (-not $vuln) { continue }
            $sev = "info"
            $vulnSev = [string]$vuln.Severity
            if ($vulnSev -and $TrivySeverityMap.ContainsKey($vulnSev)) { $sev = $TrivySeverityMap[$vulnSev] }
            $descSrc = ""
            if ($vuln.Title) { $descSrc = [string]$vuln.Title } elseif ($vuln.Description) { $descSrc = [string]$vuln.Description }
            $desc = $descSrc.Substring(0, [Math]::Min(1000, $descSrc.Length))
            $findings += @{
                title = "$($vuln.VulnerabilityID) en $($vuln.PkgName) ($targetName)"
                description = $desc
                severity = $sev
                cve_id = $vuln.VulnerabilityID
                package = $vuln.PkgName
                installed_version = $vuln.InstalledVersion
                fixed_version = $vuln.FixedVersion
            }
        }
    }
    return $findings
}

function Invoke-TrivyScan([string]$target, [string]$mode) {
    $subcommand = if ($mode -eq "fs") { "fs" } else { "image" }
    $scannerArgs = @($subcommand, "--format", "json", "--quiet", "--timeout", "8m", $target)
    $trivyCmd = Get-Command trivy -ErrorAction SilentlyContinue
    $result = Invoke-ScannerBinary -exe $trivyCmd.Source -scannerArgs $scannerArgs -timeoutSeconds 600
    if ($result.TimedOut) { return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (600s) contra $target" } }
    if (($result.ExitCode -ne 0) -and ($result.ExitCode -ne 1)) {
        $errMsg = $result.Stderr; $errMsg = $errMsg.Substring(0, [Math]::Min(2000, $errMsg.Length))
        return @{ Raw = $result.Stdout; Findings = @(); Error = $errMsg }
    }
    return @{ Raw = $result.Stdout; Findings = (Get-TrivyFindings $result.Stdout); Error = "" }
}

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

function Submit-Result([string]$jobId, [string]$status, $findings, [string]$err, [string]$rawOutput = "agente LAN (PowerShell)") {
    # Construye el body entero como objeto y lo serializa UNA vez con
    # ConvertTo-Json -- antes se armaba a mano con string concatenation
    # ("...""raw_output"":""$rawOutput""..."), lo que se rompia apenas
    # $rawOutput o $err trajeran una comilla (justo lo que trae SIEMPRE
    # un JSON real de nuclei/trivy).
    $payload = @{
        status = $status
        findings = @($findings)
        raw_output = $rawOutput
        error_message = $err
    }
    $body = $payload | ConvertTo-Json -Depth 8 -Compress
    Invoke-RestMethod -Uri "$scanUrl/agents/results/$jobId" -Method Post `
        -Headers @{ "X-Agent-Key" = $key; "Content-Type" = "application/json" } -Body $body -TimeoutSec 30 | Out-Null
}

$startupNucleiCmd = Get-Command nuclei -ErrorAction SilentlyContinue
$startupTrivyCmd = Get-Command trivy -ErrorAction SilentlyContinue
Write-Log "============================================================"
Write-Log "SentinelOps - Agente LAN (PowerShell nativo) iniciado."
Write-Log "Puertos (estilo nmap): siempre disponible, sin instalar nada."
Write-Log "nuclei: $(if ($startupNucleiCmd) { "disponible ($($startupNucleiCmd.Source))" } else { "no instalado -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "trivy:  $(if ($startupTrivyCmd) { "disponible ($($startupTrivyCmd.Source))" } else { "no instalado -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "scan-service: $scanUrl   polling cada ${pollInterval}s   (Ctrl+C para detener)"
Write-Log "============================================================"

while ($true) {
    try {
        $resp = Invoke-RestMethod -Uri "$scanUrl/agents/poll" -Method Post -Headers $headers -TimeoutSec 30
        foreach ($job in @($resp.jobs)) {
            $jobId = $job.id; $target = $job.target; $scanner = $job.scanner_type
            Write-Log "job $($jobId.Substring(0,8)): $scanner -> $target ..."

            if ($scanner -eq "nmap") {
                $hostsList = Expand-Hosts $target
                $findings = @()
                foreach ($h in $hostsList) {
                    foreach ($op in (Scan-HostPorts $h $ports)) {
                        $svc = if ($svcNames.ContainsKey($op)) { $svcNames[$op] } else { "" }
                        $findings += @{ title = "Puerto abierto $op/tcp ($svc) en $h"; description = "detectado por el Agente LAN (PowerShell, sin nmap)"; severity = "info"; port = $op; service = $svc }
                    }
                }
                Submit-Result $jobId "completed" $findings ""
                Write-Log "job $($jobId.Substring(0,8)): completado, $($findings.Count) hallazgo(s)"
                continue
            }

            if ($scanner -eq "nuclei") {
                $nucleiCmd = Get-Command nuclei -ErrorAction SilentlyContinue
                if (-not $nucleiCmd) {
                    Submit-Result $jobId "failed" @() "nuclei.exe no esta instalado en esta PC (o no esta en el PATH). Instalalo (https://github.com/projectdiscovery/nuclei#install-nuclei) y el proximo job de nuclei va a andar solo, sin reiniciar el agente."
                    Write-Log "job $($jobId.Substring(0,8)): rechazado -- nuclei no esta instalado"
                    continue
                }
                $res = Invoke-NucleiScan $target $job.options
                if ($res.Error) {
                    Submit-Result $jobId "failed" @() $res.Error $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): fallo -- $($res.Error)"
                } else {
                    Submit-Result $jobId "completed" $res.Findings "" $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): completado, $($res.Findings.Count) hallazgo(s)"
                }
                continue
            }

            if ($scanner -eq "trivy") {
                $trivyCmd = Get-Command trivy -ErrorAction SilentlyContinue
                if (-not $trivyCmd) {
                    Submit-Result $jobId "failed" @() "trivy.exe no esta instalado en esta PC (o no esta en el PATH). Instalalo (https://aquasecurity.github.io/trivy) y el proximo job de trivy va a andar solo, sin reiniciar el agente."
                    Write-Log "job $($jobId.Substring(0,8)): rechazado -- trivy no esta instalado"
                    continue
                }
                $mode = "image"
                if ($job.options -and $job.options.mode) { $mode = [string]$job.options.mode }
                $res = Invoke-TrivyScan $target $mode
                if ($res.Error) {
                    Submit-Result $jobId "failed" @() $res.Error $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): fallo -- $($res.Error)"
                } else {
                    Submit-Result $jobId "completed" $res.Findings "" $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): completado, $($res.Findings.Count) hallazgo(s)"
                }
                continue
            }

            # openvas u otro scanner desconocido: sigue sin soporte aca --
            # openvas necesita el motor completo de Greenbone (gvmd), no
            # un binario suelto que se pueda invocar como nuclei/trivy.
            Submit-Result $jobId "failed" @() "El Agente LAN no puede correr '$scanner' -- necesita el motor completo de Greenbone (gvmd), que este agente PowerShell no corre. Si '$target' es alcanzable desde internet o desde la PC del Agente Docker, proba ese agente."
            Write-Log "job $($jobId.Substring(0,8)): rechazado -- '$scanner' no soportado por este agente"
        }
    } catch {
        Write-Log "error hablando con scan-service: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $pollInterval
}
