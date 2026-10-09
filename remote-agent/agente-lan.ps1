# ==========================================================================
# SentinelOps - Agente LAN NATIVO (PowerShell puro).
# NO requiere Python, ni instalar NADA: usa PowerShell + .NET, que ya
# vienen con Windows. Corre en el host, ejecuta nuclei/trivy contra el
# target del job y reporta a scan-service. Se autentica como el agente
# "Agente LAN".
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

# --------------------------------------------------------------------------
# nuclei/trivy: si estan instalados en ESTA PC (basta con que
# `nuclei`/`trivy` respondan desde una consola cualquiera, no hace falta
# nada mas), este agente los usa de verdad -- mismos flags/restricciones
# que el driver in-container (app/scanners/nuclei.py, app/scanners/
# trivy.py) y que remote-agent/agent.py, para mantener la misma postura
# de seguridad (solo deteccion, nunca explotacion activa). Se chequea en
# CADA job, no solo al arrancar, para que instalarlos mientras el agente
# ya esta corriendo funcione sin tener que reiniciarlo. Si no estan, el
# job vuelve con un mensaje claro en vez de intentarlo.
# --------------------------------------------------------------------------
$NucleiSeverityMap = @{ critical="critical"; high="high"; medium="medium"; low="low"; info="info"; unknown="info" }
$TrivySeverityMap  = @{ CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; UNKNOWN="info" }
# Carpeta al lado del script para binarios instalados a mano (sin depender
# del PATH del sistema) -- pensada para dejar nuclei.exe/trivy.exe
# descargados oficialmente ahi mismo, en la "carpeta de programa", sin
# tocar variables de entorno de Windows. remote-agent/bin/ esta en
# .gitignore (via *.exe) -- estos binarios NUNCA se commitean al repo
# (son grandes y GitHub bloquea archivos de mas de 100MB).
$BundledBinDir = Join-Path $scriptDir "bin"

function Resolve-ScannerBinary([string]$name) {
    # PATH del sistema primero (si el operador ya lo instalo "normal"),
    # y si no esta ahi, la carpeta bin/ al lado de este script.
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $bundled = Join-Path $BundledBinDir "$name.exe"
    if (Test-Path $bundled) { return $bundled }
    return $null
}

function Invoke-ScannerBinary([string]$exe, [string[]]$scannerArgs, [int]$timeoutSeconds) {
    # Corre un binario externo (nuclei/trivy) con limite de tiempo real --
    # equivalente a subprocess.run(..., timeout=N) de Python: si se pasa
    # el timeout, lo mata y devuelve TimedOut=true en vez de colgar el
    # loop de polling para siempre.
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        # ArgumentList (la coleccion que evita tener que armar un string y
        # escapar comillas a mano) solo existe en .NET moderno -- en el
        # .NET Framework que trae Windows PowerShell 5.1 en muchas PCs
        # (la que corre este agente) la propiedad esta pero arranca en
        # $null, y .Add() sobre $null revienta con "No se puede llamar a
        # un metodo en una expresion con valor NULL". Se ve siempre en
        # nuclei/trivy porque son los primeros (y unicos) scanners que
        # arrancan un proceso externo con argumentos. Arreglo: armar el
        # string de argumentos a mano, que funciona igual en .NET
        # Framework y .NET moderno.
        $psi.Arguments = ($scannerArgs | ForEach-Object {
            if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
        }) -join ' '
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        $exited = $proc.WaitForExit($timeoutSeconds * 1000)
        if (-not $exited) {
            # Matar el ARBOL de procesos, no solo el proceso lanzado: zap.bat
            # (y otros wrappers) lanzan un java/otro hijo que sobrevivia al
            # Kill() del padre, seguia corriendo en segundo plano y dejaba
            # bloqueado el directorio de estado de ZAP para los jobs siguientes.
            try { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null } catch {}
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
    # 420s (7 min), NO 600 -- el backend considera "huerfano" (y se lo
    # puede dar a otro agente bootstrap, incluso a este mismo en su
    # proximo poll) un job 'assigned' hace 10 min o mas (ver
    # poll_agent_jobs/agent_can_claim_job en scan-service). Con el timeout
    # local en exactamente 600s (los mismos 10 min), cualquier latencia de
    # red al mandar Submit-Result alcanzaba para que el backend ya lo
    # hubiera dado de baja como huerfano -- este mismo agente lo volvia a
    # tomar en su siguiente poll y arrancaba nuclei de cero, sin llegar
    # nunca a un estado final (el contador de "corriendo hace" volvia a 0
    # una y otra vez). Con margen de 3 min de sobra, Submit-Result llega
    # siempre antes de que el backend lo de por huerfano.
    $result = Invoke-ScannerBinary -exe (Resolve-ScannerBinary "nuclei") -scannerArgs $scannerArgs -timeoutSeconds 420
    if ($result.TimedOut) { return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (420s) contra $target" } }
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

function Get-TrivyPackages([string]$rawJson) {
    # Inventario COMPLETO de paquetes (Results[].Packages, requiere
    # --list-all-pkgs) -- alimenta "Imagenes y Paquetes". Mismo shape que
    # app/scanners/trivy.py::_parse_trivy_packages.
    $packages = New-Object System.Collections.Generic.List[object]
    if (-not $rawJson.Trim()) { return ,$packages.ToArray() }
    try { $payload = $rawJson | ConvertFrom-Json } catch { return ,$packages.ToArray() }
    foreach ($result in @($payload.Results)) {
        if (-not $result) { continue }
        $pkgType = [string]$result.Type
        if (-not $pkgType) { $pkgType = [string]$result.Class }
        foreach ($pkg in @($result.Packages)) {
            if (-not $pkg -or -not $pkg.Name) { continue }
            $layer = $null
            if ($pkg.Layer -and $pkg.Layer.DiffID) { $layer = [string]$pkg.Layer.DiffID }
            $packages.Add(@{
                target = [string]$result.Target
                type = $pkgType
                name = [string]$pkg.Name
                version = [string]$pkg.Version
                arch = [string]$pkg.Arch
                layer = $layer
            })
        }
    }
    return ,$packages.ToArray()
}

function Invoke-TrivyScan([string]$target, [string]$mode) {
    $subcommand = if ($mode -eq "fs") { "fs" } else { "image" }
    # Mismo motivo que en Invoke-NucleiScan: el timeout de trivy (interno,
    # via --timeout) y el limite duro de este wrapper tienen que quedar
    # los dos comodos por debajo de los 10 min que usa el backend para
    # recuperar un job 'assigned' huerfano -- si no, el backend se lo
    # puede volver a repartir antes de que Submit-Result llegue a avisar
    # que termino (o que hizo timeout), y el job nunca sale de "assigned".
    # --list-all-pkgs: ademas de las vulnerabilidades, lista TODOS los
    # paquetes detectados (para "Imagenes y Paquetes").
    $scannerArgs = @($subcommand, "--format", "json", "--quiet", "--timeout", "6m", "--list-all-pkgs", $target)
    $result = Invoke-ScannerBinary -exe (Resolve-ScannerBinary "trivy") -scannerArgs $scannerArgs -timeoutSeconds 420
    if ($result.TimedOut) { return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (420s) contra $target" } }
    if (($result.ExitCode -ne 0) -and ($result.ExitCode -ne 1)) {
        $errMsg = $result.Stderr; $errMsg = $errMsg.Substring(0, [Math]::Min(2000, $errMsg.Length))
        return @{ Raw = $result.Stdout; Findings = @(); Error = $errMsg }
    }
    return @{ Raw = $result.Stdout; Findings = (Get-TrivyFindings $result.Stdout); Packages = (Get-TrivyPackages $result.Stdout); Error = "" }
}

function ConvertTo-JsonFindingsArray($items) {
    # ConvertTo-Json de PowerShell tiene un bug clasico y muy documentado:
    # un array de EXACTAMENTE un elemento se serializa como el objeto
    # suelto, sin corchetes ("findings": {...} en vez de "findings":
    # [{...}]) -- eso rompe la validacion del backend (findings: list[dict],
    # Pydantic espera una lista) justo cuando nuclei/trivy encuentran UN
    # solo hallazgo. Con 0 (siempre serializa "[]" bien) o con 2+ (siempre
    # serializa como lista bien) nunca se vio -- por eso los rechazos por
    # binario faltante (0 hallazgos) andaban perfecto y nuclei/trivy
    # tiraban 422 justo cuando encontraban algo.
    # Serializamos cada elemento por separado y lo juntamos a mano entre
    # corchetes, evitando el bug de raiz en vez de esquivarlo.
    $arr = @($items)
    if ($arr.Count -eq 0) { return "[]" }
    $parts = foreach ($item in $arr) { $item | ConvertTo-Json -Depth 6 -Compress }
    return "[" + ($parts -join ",") + "]"
}

function Submit-Result([string]$jobId, [string]$status, $findings, [string]$err, [string]$rawOutput = "agente LAN (PowerShell)", $packages = $null) {
    # Con --list-all-pkgs el JSON crudo de trivy puede pesar varios MB: el
    # backend igual lo recorta a 200 KB, asi que no tiene sentido mandarlo entero.
    if ($rawOutput.Length -gt 200000) { $rawOutput = $rawOutput.Substring(0, 200000) }
    # Los campos escalares los serializa ConvertTo-Json normal (ahi no hay
    # bug); "findings" se arma aparte con ConvertTo-JsonFindingsArray (ver
    # arriba) y se inserta a mano en el mismo objeto -- reemplazando el
    # "}" de cierre por ',"findings":<array>}'. Antes se armaba a mano con
    # string concatenation entera ("...""raw_output"":""$rawOutput""..."),
    # lo que se rompia apenas $rawOutput o $err trajeran una comilla (justo
    # lo que trae SIEMPRE un JSON real de nuclei/trivy) -- por eso ahora
    # solo el array de findings se toca a mano, todo lo demas via
    # ConvertTo-Json real.
    $scalarPayload = (@{ status = $status; raw_output = $rawOutput; error_message = $err } | ConvertTo-Json -Depth 4 -Compress).TrimEnd()
    $findingsJson = ConvertTo-JsonFindingsArray $findings
    $packagesPart = ""
    if ($packages -and @($packages).Count -gt 0) {
        # Solo trivy: inventario completo de paquetes (mismo armado a mano del
        # array que findings, por el mismo bug de 1 solo elemento).
        $packagesPart = ',"packages":' + (ConvertTo-JsonFindingsArray $packages)
    }
    $body = $scalarPayload.Substring(0, $scalarPayload.Length - 1) + ',"findings":' + $findingsJson + $packagesPart + '}'
    # Windows PowerShell 5.1 manda -Body <string> con la codificacion ANSI de
    # la maquina, no UTF-8, aunque el Content-Type diga utf-8 -- si el JSON
    # de nuclei/trivy trae UN SOLO caracter no-ASCII (tildes, comillas
    # tipograficas, guiones largos -- cosa que un CVE real trae seguro) el
    # body llega corrupto y el server lo rechaza con 400 Bad Request antes
    # de mirar el contenido. Nunca habia pasado porque antes el unico
    # raw_output que se mandaba era el string fijo "agente LAN (PowerShell)",
    # puro ASCII. Mandamos los bytes UTF-8 ya codificados a mano para
    # evitar el problema de una vez.
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    Invoke-RestMethod -Uri "$scanUrl/agents/results/$jobId" -Method Post `
        -Headers @{ "X-Agent-Key" = $key } -ContentType "application/json; charset=utf-8" `
        -Body $bodyBytes -TimeoutSec 30 | Out-Null
}

# ==========================================================================
# Sumados por directiva de expansion comercial (Manu, 2026) -- zap/
# semgrep/gitleaks/yara (ver remote-agent/agent.py y los drivers
# equivalentes en backend/services/scan-service/app/scanners/ para la
# licencia/alcance exacto de cada uno). zeek/falco NO se implementan en
# este agente nativo de Windows -- son "jobs de duracion fija" que
# necesitan captura de paquetes/acceso a eBPF de un kernel Linux que no
# existe en PowerShell/Windows nativo (ver el rechazo explicito mas
# abajo, en el loop principal) -- usa el Agente Docker (remote-agent/
# agent.py, dentro de un contenedor Linux) para esos dos.
# ==========================================================================

# Reglas PROPIAS de SentinelOps para semgrep/yara -- NUNCA un ruleset de
# terceros (ver rules/semgrep/sentinelops-rules.yml y
# rules/yara/sentinelops.yar en la raiz del repo para el porque). Default:
# relativo a $root (este script vive en remote-agent/, con backend/ al
# lado en un clone completo del repo) -- overridable por si se copian a
# otro lado.
$SemgrepRulesDir = if ($env:SENTINELOPS_SEMGREP_RULES_DIR) { $env:SENTINELOPS_SEMGREP_RULES_DIR } else { Join-Path $root "backend\services\scan-service\rules\semgrep" }
$YaraRulesFile = if ($env:SENTINELOPS_YARA_RULES_FILE) { $env:SENTINELOPS_YARA_RULES_FILE } else { Join-Path $root "backend\services\scan-service\rules\yara\sentinelops.yar" }
$ZapHomeDir = if ($env:SENTINELOPS_ZAP_HOME_DIR) { $env:SENTINELOPS_ZAP_HOME_DIR } else { Join-Path $env:USERPROFILE ".ZAP" }

function Resolve-CodeTarget([string]$targetValue) {
    # Devuelve @{ Path; TmpDir (a borrar despues, o $null); Error }. Si
    # targetValue es una URL git clonable (http/https), la clona a un
    # directorio temporal; si es un path local que YA existe en esta PC,
    # se usa directo.
    if ($targetValue -match '^(https?)://') {
        $gitExe = Resolve-ScannerBinary "git"
        if (-not $gitExe) {
            return @{ Path = $null; TmpDir = $null; Error = "git no esta instalado o no esta en el PATH de esta maquina" }
        }
        $tmpDir = Join-Path $env:TEMP ("sentinelops-clone-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $result = Invoke-ScannerBinary -exe $gitExe -scannerArgs @("clone", "--single-branch", $targetValue, $tmpDir) -timeoutSeconds 180
        if ($result.TimedOut) {
            return @{ Path = $null; TmpDir = $tmpDir; Error = "timeout clonando el repositorio (180s)" }
        }
        if ($result.ExitCode -ne 0) {
            $errText = $result.Stderr
            $errText = $errText.Substring(0, [Math]::Min(2000, $errText.Length))
            return @{ Path = $null; TmpDir = $tmpDir; Error = $errText }
        }
        return @{ Path = $tmpDir; TmpDir = $tmpDir; Error = $null }
    }
    if ((Test-Path $targetValue -PathType Container) -or (Test-Path $targetValue -PathType Leaf)) {
        return @{ Path = $targetValue; TmpDir = $null; Error = $null }
    }
    return @{ Path = $null; TmpDir = $null; Error = "target '$targetValue' no es una URL git clonable (http/https) ni un path existente en esta maquina" }
}

# --- Gitleaks (secretos en historial de git, MIT) ------------------------
function Get-GitleaksSeverity([string]$ruleId) {
    $rule = ""
    if ($ruleId) { $rule = $ruleId.ToLower() }
    foreach ($m in @("private-key", "aws", "gcp", "azure", "service-account")) { if ($rule -like "*$m*") { return "critical" } }
    foreach ($m in @("token", "api-key", "apikey", "secret", "password", "generic")) { if ($rule -like "*$m*") { return "high" } }
    return "medium"
}

function Invoke-GitleaksScan([string]$targetValue) {
    $resolved = Resolve-CodeTarget $targetValue
    try {
        if ($resolved.Error) { return @{ Raw = ""; Findings = @(); Error = $resolved.Error } }
        $gitleaksExe = Resolve-ScannerBinary "gitleaks"
        if (-not $gitleaksExe) { return @{ Raw = ""; Findings = @(); Error = "gitleaks no esta instalado (ni en el PATH ni en $BundledBinDir)" } }
        $reportPath = Join-Path $env:TEMP ("gitleaks-report-" + [guid]::NewGuid().ToString("N") + ".json")
        $noGit = -not (Test-Path (Join-Path $resolved.Path ".git"))
        $gitleaksArgs = @("detect", "--source", $resolved.Path, "--report-format", "json", "--report-path", $reportPath, "--exit-code", "0", "--no-banner")
        if ($noGit) { $gitleaksArgs += "--no-git" }
        $result = Invoke-ScannerBinary -exe $gitleaksExe -scannerArgs $gitleaksArgs -timeoutSeconds 300
        if ($result.TimedOut) { return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (300s)" } }
        if ($result.ExitCode -ne 0) {
            $errText = $result.Stderr; $errText = $errText.Substring(0, [Math]::Min(2000, $errText.Length))
            return @{ Raw = ""; Findings = @(); Error = $errText }
        }
        $findings = @()
        $rawJson = $null
        if (Test-Path $reportPath) {
            $rawJson = Get-Content $reportPath -Raw -ErrorAction SilentlyContinue
            if ($rawJson) {
                try { $items = @($rawJson | ConvertFrom-Json) } catch { $items = @() }
                foreach ($item in $items) {
                    if (-not $item) { continue }
                    $ruleId = [string]$item.RuleID
                    $filePath = [string]$item.File
                    $findings += @{
                        title = "Secreto detectado ($ruleId) en $filePath"
                        description = [string]$item.Description
                        severity = (Get-GitleaksSeverity $ruleId)
                        cve_id = $null
                        service = $null
                    }
                }
            }
            Remove-Item $reportPath -ErrorAction SilentlyContinue
        }
        return @{ Raw = $rawJson; Findings = $findings; Error = "" }
    } finally {
        if ($resolved.TmpDir -and (Test-Path $resolved.TmpDir)) { Remove-Item $resolved.TmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# --- Semgrep (SAST, motor LGPL-2.1, SOLO reglas propias) -----------------
function Invoke-SemgrepScan([string]$targetValue) {
    $resolved = Resolve-CodeTarget $targetValue
    try {
        if ($resolved.Error) { return @{ Raw = ""; Findings = @(); Error = $resolved.Error } }
        $semgrepExe = Resolve-ScannerBinary "semgrep"
        if (-not $semgrepExe) { return @{ Raw = ""; Findings = @(); Error = "semgrep no esta instalado (ni en el PATH ni en $BundledBinDir)" } }
        # --config SIEMPRE una ruta propia -- NUNCA 'auto'/'p/...' (ver
        # rules/semgrep/sentinelops-rules.yml para el porque).
        $semgrepArgs = @("scan", "--config", $SemgrepRulesDir, "--json", "--quiet", "--metrics=off", "--timeout", "60", $resolved.Path)
        $result = Invoke-ScannerBinary -exe $semgrepExe -scannerArgs $semgrepArgs -timeoutSeconds 420
        if ($result.TimedOut) { return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (420s)" } }
        if (($result.ExitCode -ne 0) -and ($result.ExitCode -ne 1)) {
            $errText = $result.Stderr; $errText = $errText.Substring(0, [Math]::Min(2000, $errText.Length))
            return @{ Raw = $result.Stdout; Findings = @(); Error = $errText }
        }
        $findings = @()
        if ($result.Stdout.Trim()) {
            try { $data = $result.Stdout | ConvertFrom-Json } catch { $data = $null }
            if ($data -and $data.results) {
                foreach ($r in @($data.results)) {
                    if (-not $r) { continue }
                    $sev = "info"
                    $rawSev = [string]$r.extra.severity
                    if ($rawSev -eq "ERROR") { $sev = "high" } elseif ($rawSev -eq "WARNING") { $sev = "medium" }
                    $findings += @{
                        title = "$($r.check_id) en $($r.path)"
                        description = [string]$r.extra.message
                        severity = $sev
                        cve_id = $null
                        service = $null
                    }
                }
            }
        }
        return @{ Raw = $result.Stdout; Findings = $findings; Error = "" }
    } finally {
        if ($resolved.TmpDir -and (Test-Path $resolved.TmpDir)) { Remove-Item $resolved.TmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# --- YARA (patrones/indicadores conocidos en archivos, BSD-3-Clause) -----
function Get-YaraSeverity([string]$ruleName) {
    switch ($ruleName) {
        "SentinelOps_EICAR_Test_File" { return "info" }
        "SentinelOps_Embedded_PE_In_NonExecutable" { return "high" }
        "SentinelOps_PHP_Obfuscated_Webshell_Pattern" { return "critical" }
        "SentinelOps_Suspicious_Obfuscated_PowerShell" { return "high" }
        "SentinelOps_Python_Reverse_Shell_Oneliner" { return "critical" }
        default { return "medium" }
    }
}

function Invoke-YaraScan([string]$targetValue) {
    if (-not (Test-Path $targetValue)) {
        return @{ Raw = ""; Findings = @(); Error = "target '$targetValue' no existe en esta maquina" }
    }
    $yaraExe = Resolve-ScannerBinary "yara"
    if (-not $yaraExe) { return @{ Raw = ""; Findings = @(); Error = "yara no esta instalado (ni en el PATH ni en $BundledBinDir)" } }
    $yaraArgs = @("-s")
    if (Test-Path $targetValue -PathType Container) { $yaraArgs += "-r" }
    $yaraArgs += @($YaraRulesFile, $targetValue)
    $result = Invoke-ScannerBinary -exe $yaraExe -scannerArgs $yaraArgs -timeoutSeconds 300
    if ($result.TimedOut) { return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (300s)" } }
    if ($result.ExitCode -ne 0) {
        $errText = $result.Stderr; $errText = $errText.Substring(0, [Math]::Min(2000, $errText.Length))
        return @{ Raw = $result.Stdout; Findings = @(); Error = $errText }
    }
    $findings = @()
    foreach ($line in ($result.Stdout -split "`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        # "0xOFFSET:$id: contenido" -- linea de detalle de -s, SIN indentar
        # en esta version de yara (bug real: se asumia indentada con
        # tab/espacio y nunca se filtraba). Un nombre de regla YARA nunca
        # empieza con un digito, asi que este patron nunca se confunde con
        # una linea real "REGLA archivo".
        if ($trimmed -match '^0x[0-9a-fA-F]+:') { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -lt 2) { continue }
        $ruleName = $parts[0]; $filePath = $parts[1]
        $findings += @{
            title = "YARA: $ruleName en $filePath"
            description = "El archivo '$filePath' coincide con la regla YARA '$ruleName'."
            severity = (Get-YaraSeverity $ruleName)
            cve_id = $null
            service = $null
        }
    }
    return @{ Raw = $result.Stdout; Findings = $findings; Error = "" }
}

# --- OWASP ZAP (DAST pasivo, Apache 2.0) ---------------------------------
# Automation Framework (-autorun plan): spider acotado + analisis PASIVO +
# reporte traditional-json. NO se usa -quickurl: verificado con ZAP 2.16, ese
# modo lanza el escaneo ACTIVO completo (lentisimo y con payloads de ataque),
# que era lo que dejaba los jobs de ZAP "assigned" por muchisimo tiempo. Con
# este plan el job termina en ~4 minutos como maximo.
function Invoke-ZapScan([string]$targetValue) {
    if (-not ($targetValue.StartsWith("http://") -or $targetValue.StartsWith("https://"))) {
        return @{ Raw = ""; Findings = @(); Error = "target invalido para ZAP: debe ser una URL http:// o https://" }
    }
    $zapExe = Resolve-ScannerBinary "zap"
    if (-not $zapExe) { $zapExe = Resolve-ScannerBinary "zap.bat" }
    if (-not $zapExe) {
        return @{ Raw = ""; Findings = @(); Error = "ZAP no esta instalado (ni 'zap'/'zap.bat' en el PATH ni en $BundledBinDir) -- instalalo desde https://www.zaproxy.org/download/" }
    }
    $zapWorkDir = Join-Path $env:TEMP ("zap-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $zapWorkDir -Force | Out-Null
    $reportPath = Join-Path $zapWorkDir "zap-report.json"
    $planPath = Join-Path $zapWorkDir "zap-plan.yaml"
    # JSON es YAML valido; ConvertTo-Json solo se usa para escapar strings.
    $urlJson = ($targetValue | ConvertTo-Json -Compress)
    $dirJson = ($zapWorkDir | ConvertTo-Json -Compress)
    $planJson = '{"env":{"contexts":[{"name":"sentinelops","urls":[' + $urlJson + ']}],"parameters":{"failOnError":false,"failOnWarning":false,"progressToStdout":false}},"jobs":[{"type":"spider","parameters":{"maxDuration":2,"maxDepth":5}},{"type":"passiveScan-wait","parameters":{"maxDuration":2}},{"type":"report","parameters":{"template":"traditional-json","reportDir":' + $dirJson + ',"reportFile":"zap-report.json"}}]}'
    [System.IO.File]::WriteAllText($planPath, $planJson, (New-Object System.Text.UTF8Encoding($false)))
    $zapArgs = @("-cmd", "-dir", $ZapHomeDir, "-autorun", $planPath)
    $result = Invoke-ScannerBinary -exe $zapExe -scannerArgs $zapArgs -timeoutSeconds 420
    if ($result.TimedOut) {
        Remove-Item $zapWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        return @{ Raw = ""; Findings = @(); Error = "timeout de escaneo (420s)" }
    }
    if (-not (Test-Path $reportPath)) {
        $errText = $result.Stderr
        if (-not $errText) { $errText = "ZAP no genero un reporte" }
        Remove-Item $zapWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        return @{ Raw = $result.Stdout; Findings = @(); Error = $errText.Substring(0, [Math]::Min(2000, $errText.Length)) }
    }
    $rawJson = Get-Content $reportPath -Raw -ErrorAction SilentlyContinue
    Remove-Item $zapWorkDir -Recurse -Force -ErrorAction SilentlyContinue
    $findings = @()
    if ($rawJson) {
        try { $data = $rawJson | ConvertFrom-Json } catch { $data = $null }
        $sevMap = @{ high = "high"; medium = "medium"; low = "low"; informational = "info" }
        foreach ($site in @($data.site)) {
            if (-not $site) { continue }
            foreach ($alert in @($site.alerts)) {
                if (-not $alert) { continue }
                $riskdesc = [string]$alert.riskdesc
                $riskKey = "informational"
                if ($riskdesc) { $riskKey = ($riskdesc.Trim().Split(" ")[0]).ToLower() }
                $sev = "info"
                if ($sevMap.ContainsKey($riskKey)) { $sev = $sevMap[$riskKey] }
                $uri = ""
                $instances = @($alert.instances)
                if (($instances.Count -gt 0) -and $instances[0].uri) { $uri = [string]$instances[0].uri }
                $findings += @{
                    title = [string]$alert.name
                    description = [string]$alert.desc
                    severity = $sev
                    cve_id = $null
                    service = $uri
                }
            }
        }
    }
    return @{ Raw = $rawJson; Findings = $findings; Error = "" }
}

$startupNucleiPath = Resolve-ScannerBinary "nuclei"
$startupTrivyPath = Resolve-ScannerBinary "trivy"
$startupZapPath = Resolve-ScannerBinary "zap"
if (-not $startupZapPath) { $startupZapPath = Resolve-ScannerBinary "zap.bat" }
$startupSemgrepPath = Resolve-ScannerBinary "semgrep"
$startupGitleaksPath = Resolve-ScannerBinary "gitleaks"
$startupYaraPath = Resolve-ScannerBinary "yara"
Write-Log "============================================================"
Write-Log "SentinelOps - Agente LAN (PowerShell nativo) iniciado."
Write-Log "nuclei:   $(if ($startupNucleiPath) { "disponible ($startupNucleiPath)" } else { "no instalado (ni en el PATH ni en $BundledBinDir) -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "trivy:    $(if ($startupTrivyPath) { "disponible ($startupTrivyPath)" } else { "no instalado (ni en el PATH ni en $BundledBinDir) -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "zap:      $(if ($startupZapPath) { "disponible ($startupZapPath)" } else { "no instalado (ni en el PATH ni en $BundledBinDir) -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "semgrep:  $(if ($startupSemgrepPath) { "disponible ($startupSemgrepPath)" } else { "no instalado (ni en el PATH ni en $BundledBinDir) -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "gitleaks: $(if ($startupGitleaksPath) { "disponible ($startupGitleaksPath)" } else { "no instalado (ni en el PATH ni en $BundledBinDir) -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "yara:     $(if ($startupYaraPath) { "disponible ($startupYaraPath)" } else { "no instalado (ni en el PATH ni en $BundledBinDir) -- esos jobs van a fallar con un mensaje claro" })"
Write-Log "zeek/falco: NO soportados por el Agente LAN nativo (requieren captura de paquetes/eBPF de Linux) -- usa el Agente Docker para esos dos."
Write-Log "scan-service: $scanUrl   polling cada ${pollInterval}s   (Ctrl+C para detener)"
Write-Log "============================================================"

while ($true) {
    try {
        $resp = Invoke-RestMethod -Uri "$scanUrl/agents/poll" -Method Post -Headers $headers -TimeoutSec 30
        foreach ($job in @($resp.jobs)) {
            $jobId = $job.id; $target = $job.target; $scanner = $job.scanner_type
            Write-Log "job $($jobId.Substring(0,8)): $scanner -> $target ..."

            if ($scanner -eq "nuclei") {
                if (-not (Resolve-ScannerBinary "nuclei")) {
                    Submit-Result $jobId "failed" @() "nuclei no esta instalado (ni en el PATH ni en $BundledBinDir). Instalalo (https://github.com/projectdiscovery/nuclei#install-nuclei) -- poniendo nuclei.exe en esa carpeta alcanza, no hace falta el PATH -- y el proximo job de nuclei va a andar solo, sin reiniciar el agente."
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
                if (-not (Resolve-ScannerBinary "trivy")) {
                    Submit-Result $jobId "failed" @() "trivy no esta instalado (ni en el PATH ni en $BundledBinDir). Instalalo (https://aquasecurity.github.io/trivy) -- poniendo trivy.exe en esa carpeta alcanza, no hace falta el PATH -- y el proximo job de trivy va a andar solo, sin reiniciar el agente."
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
                    Submit-Result $jobId "completed" $res.Findings "" $res.Raw $res.Packages
                    Write-Log "job $($jobId.Substring(0,8)): completado, $($res.Findings.Count) hallazgo(s), $(@($res.Packages).Count) paquete(s)"
                }
                continue
            }

            if ($scanner -eq "zap") {
                if (-not (Resolve-ScannerBinary "zap") -and -not (Resolve-ScannerBinary "zap.bat")) {
                    Submit-Result $jobId "failed" @() "ZAP no esta instalado (ni 'zap'/'zap.bat' en el PATH ni en $BundledBinDir). Instalalo desde https://www.zaproxy.org/download/ -- y el proximo job de zap va a andar solo, sin reiniciar el agente."
                    Write-Log "job $($jobId.Substring(0,8)): rechazado -- ZAP no esta instalado"
                    continue
                }
                $res = Invoke-ZapScan $target
                if ($res.Error) {
                    Submit-Result $jobId "failed" @() $res.Error $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): fallo -- $($res.Error)"
                } else {
                    Submit-Result $jobId "completed" $res.Findings "" $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): completado, $($res.Findings.Count) hallazgo(s)"
                }
                continue
            }

            if ($scanner -eq "semgrep") {
                if (-not (Resolve-ScannerBinary "semgrep")) {
                    Submit-Result $jobId "failed" @() "semgrep no esta instalado (ni en el PATH ni en $BundledBinDir). Instalalo (pip install semgrep) -- y el proximo job de semgrep va a andar solo, sin reiniciar el agente."
                    Write-Log "job $($jobId.Substring(0,8)): rechazado -- semgrep no esta instalado"
                    continue
                }
                $res = Invoke-SemgrepScan $target
                if ($res.Error) {
                    Submit-Result $jobId "failed" @() $res.Error $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): fallo -- $($res.Error)"
                } else {
                    Submit-Result $jobId "completed" $res.Findings "" $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): completado, $($res.Findings.Count) hallazgo(s)"
                }
                continue
            }

            if ($scanner -eq "gitleaks") {
                if (-not (Resolve-ScannerBinary "gitleaks")) {
                    Submit-Result $jobId "failed" @() "gitleaks no esta instalado (ni en el PATH ni en $BundledBinDir). Instalalo (https://github.com/gitleaks/gitleaks#installing) -- y el proximo job de gitleaks va a andar solo, sin reiniciar el agente."
                    Write-Log "job $($jobId.Substring(0,8)): rechazado -- gitleaks no esta instalado"
                    continue
                }
                $res = Invoke-GitleaksScan $target
                if ($res.Error) {
                    Submit-Result $jobId "failed" @() $res.Error $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): fallo -- $($res.Error)"
                } else {
                    Submit-Result $jobId "completed" $res.Findings "" $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): completado, $($res.Findings.Count) hallazgo(s)"
                }
                continue
            }

            if ($scanner -eq "yara") {
                if (-not (Resolve-ScannerBinary "yara")) {
                    Submit-Result $jobId "failed" @() "yara no esta instalado (ni en el PATH ni en $BundledBinDir). Instalalo (https://virustotal.github.io/yara/) -- y el proximo job de yara va a andar solo, sin reiniciar el agente."
                    Write-Log "job $($jobId.Substring(0,8)): rechazado -- yara no esta instalado"
                    continue
                }
                $res = Invoke-YaraScan $target
                if ($res.Error) {
                    Submit-Result $jobId "failed" @() $res.Error $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): fallo -- $($res.Error)"
                } else {
                    Submit-Result $jobId "completed" $res.Findings "" $res.Raw
                    Write-Log "job $($jobId.Substring(0,8)): completado, $($res.Findings.Count) hallazgo(s)"
                }
                continue
            }

            if (($scanner -eq "zeek") -or ($scanner -eq "falco")) {
                Submit-Result $jobId "failed" @() "'$scanner' no esta soportado en el Agente LAN nativo de Windows (necesita captura de paquetes / eBPF de Linux). Usa el Agente Docker de SentinelOps para correr este scanner."
                Write-Log "job $($jobId.Substring(0,8)): rechazado -- '$scanner' requiere el Agente Docker, no el Agente LAN nativo"
                continue
            }

            # Scanner desconocido: este agente no reconoce ese nombre.
            Submit-Result $jobId "failed" @() "El Agente LAN (PowerShell) no reconoce el scanner '$scanner'. Los soportados son nuclei, trivy, zap, semgrep, gitleaks y yara (zeek y falco requieren el Agente Docker)."
            Write-Log "job $($jobId.Substring(0,8)): rechazado -- '$scanner' no soportado por este agente"
        }
    } catch {
        Write-Log "error hablando con scan-service: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $pollInterval
}
