# Prueba de punta a punta de los scanners de TERO Security contra TU stack real.
# Inicia sesion, lanza un escaneo de cada tipo (local en scan-service y por cada
# agente remoto) y muestra una tabla OK / FALLA con el motivo.
#
# Uso (desde la raiz del repo, PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\probar-scanners.ps1
# Opciones:
#   -NucleiTarget http://scanme.nmap.org   host publico de pruebas (permitido por nmap.org)
#   -IncluirZap                            suma ZAP (tarda varios minutos)
#   -SoloAgentes                           saltea los escaneos locales y las subidas (reintento rapido)
#   -TimeoutSeg 300                        espera maxima por escaneo
#   -AuthUrl http://localhost:8001 -ScanUrl http://localhost:8003
# La password se pide por consola (no queda en ningun archivo).
param(
    [string]$AuthUrl = "http://localhost:8001",
    [string]$ScanUrl = "http://localhost:8003",
    [string]$NucleiTarget = "http://scanme.nmap.org",
    [string]$TrivyImage = "alpine:3.19",
    [int]$TimeoutSeg = 300,
    [switch]$IncluirZap,
    [switch]$SoloAgentes
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Say($m, $c = "Gray") { Write-Host $m -ForegroundColor $c }

# ---------- login ----------
$email = Read-Host "Email de TERO Security"
$sec = Read-Host "Password" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
$body = @{ email = $email; password = $plain }
$totp = Read-Host "Codigo MFA (Enter si no usas MFA)"
if ($totp) { $body.totp_code = $totp }
try {
    $tok = Invoke-RestMethod -Method Post -Uri "$AuthUrl/auth/login" -ContentType "application/json" -Body ($body | ConvertTo-Json)
} catch {
    throw "No pude iniciar sesion en $AuthUrl (${_}). Esta levantado auth-service? docker compose ps"
}
$plain = $null
$H = @{ Authorization = "Bearer $($tok.access_token)" }
Say "Sesion iniciada." Green

function Api($method, $path, $obj = $null) {
    $p = @{ Method = $method; Uri = "$ScanUrl$path"; Headers = $H }
    if ($obj -ne $null) { $p.ContentType = "application/json"; $p.Body = ($obj | ConvertTo-Json -Depth 6) }
    Invoke-RestMethod @p
}

# Windows PowerShell 5.1 entrega un array JSON como UN solo objeto anidado: se aplana aca.
function ApiList($path) {
    $r = Api Get $path
    if ($null -eq $r) { return @() }
    return @($r | ForEach-Object { $_ })
}

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row($grupo, $scanner, $estado, $hallazgos, $detalle) {
    $d = [string]$detalle
    if ($d.Length -gt 160) { $d = $d.Substring(0, 160) + "..." }
    $rows.Add([pscustomobject]@{ Grupo = $grupo; Scanner = $scanner; Estado = $estado; Hallazgos = $hallazgos; Detalle = $d })
}

function Wait-Job($path, $terminales) {
    $t0 = Get-Date
    while ($true) {
        Start-Sleep -Seconds 4
        $j = Api Get $path
        if ($terminales -contains $j.status) { return $j }
        if (((Get-Date) - $t0).TotalSeconds -gt $TimeoutSeg) { return $j }
    }
}

function Cerrar($grupo, $scanner, $j, $okStates) {
    if ($okStates -contains $j.status) {
        $n = @($j.findings).Count
        Add-Row $grupo $scanner "OK" $n ""
    } elseif ($j.status -in @("pending", "running", "assigned")) {
        Add-Row $grupo $scanner "TIMEOUT" "-" "Sigue en '$($j.status)' tras ${TimeoutSeg}s (agente apagado? sin red?)"
    } else {
        Add-Row $grupo $scanner "FALLA" "-" "$($j.status): $($j.error_message)"
    }
}

# ---------- 0) disponibilidad de binarios en scan-service ----------
if (-not $SoloAgentes) {
Say "`n[0] Binarios en scan-service..." Cyan
$st = Api Get "/scanners/status"
foreach ($p in $st.PSObject.Properties) {
    if ($p.Value) { Add-Row "binarios" $p.Name "OK" "-" "instalado" }
    else { Add-Row "binarios" $p.Name "FALLA" "-" "binario no disponible en el contenedor (reconstruir: docker compose up -d --build scan-service)" }
}

# ---------- 1) escaneos locales (scan-service) ----------
Say "[1] Escaneos locales..." Cyan
$casos = @(
    @{ s = "trivy";  t = $TrivyImage;    o = @{} },
    @{ s = "nuclei"; t = $NucleiTarget;  o = @{ tags = "tech" } }
)
if ($IncluirZap) { $casos += @{ s = "zap"; t = $NucleiTarget; o = @{} } }
foreach ($c in $casos) {
    Say "   - $($c.s) -> $($c.t)"
    try {
        $j = Api Post "/scans" @{ name = "prueba-$($c.s)"; scanner_type = $c.s; target = $c.t; options = $c.o }
        $j = Wait-Job "/scans/$($j.id)" @("completed", "failed", "scanner_unavailable", "cancelled")
        Cerrar "local" $c.s $j @("completed")
    } catch { Add-Row "local" $c.s "FALLA" "-" $_.Exception.Message }
}

# ---------- 2) subidas (trivy sobre manifiesto, yara) ----------
Say "[2] Subida de archivos..." Cyan
$tmp = Join-Path $env:TEMP ("sentinel-prueba-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
Set-Content -Path (Join-Path $tmp "requirements.txt") -Value "flask==0.12`nrequests==2.19.0" -Encoding ASCII
Set-Content -Path (Join-Path $tmp "inofensivo.txt") -Value "archivo de prueba inofensivo para YARA" -Encoding ASCII
$curl = (Get-Command curl.exe -ErrorAction SilentlyContinue)
if (-not $curl) {
    Add-Row "subida" "trivy/yara" "FALLA" "-" "No encuentro curl.exe (Windows 10+ lo trae)"
} else {
    foreach ($u in @(@{ n = "trivy (requirements.txt)"; ep = "/scans/upload"; f = "file"; file = "requirements.txt"; ok = 1 },
                     @{ n = "yara (inofensivo.txt)"; ep = "/scans/upload-yara"; f = "files"; file = "inofensivo.txt"; ok = 1 })) {
        Say "   - $($u.n)"
        try {
            $raw = & curl.exe -s -X POST "$ScanUrl$($u.ep)" -H "Authorization: Bearer $($tok.access_token)" `
                -F "$($u.f)=@$(Join-Path $tmp $u.file)" -F "name=prueba"
            $j = $raw | ConvertFrom-Json
            if (-not $j.id) { Add-Row "subida" $u.n "FALLA" "-" $raw; continue }
            $j = Wait-Job "/scans/$($j.id)" @("completed", "failed", "scanner_unavailable", "cancelled")
            Cerrar "subida" $u.n $j @("completed")
        } catch { Add-Row "subida" $u.n "FALLA" "-" $_.Exception.Message }
    }
}
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

} # fin de -not $SoloAgentes

# ---------- 3) agentes remotos ----------
Say "[3] Agentes remotos..." Cyan
try {
$agents = @(ApiList "/agents")
if ($agents.Count -eq 0) { Add-Row "agentes" "-" "FALLA" "-" "No hay agentes registrados (revisar BOOTSTRAP_AGENTS en .env y logs de scan-service)" }
foreach ($a in $agents) {
    $g = "agente: $($a.name)"
    if (-not $a.bootstrap_api_key) {
        Add-Row $g "-" "OMITIDO" "-" "No veo la key de este agente: si tu cuenta es Solo lectura (viewer), subile el rol a Analista en Usuarios y roles; si el agente se creo a mano, su key no se puede leer desde la API"
        continue
    }
    $vistoHace = $null
    if ($a.last_seen_at) { $vistoHace = [int]((Get-Date).ToUniversalTime() - ([datetime]$a.last_seen_at).ToUniversalTime()).TotalSeconds }
    if ($vistoHace -eq $null -or $vistoHace -gt 120) {
        Add-Row $g "-" "FALLA" "-" "Agente sin latido reciente (visto hace $vistoHace s). Esta corriendo? Revisa su log / docker compose logs remote-agent"
        continue
    }
    $lista = @(@{ s = "nuclei"; t = $NucleiTarget; o = @{ tags = "tech" } })
    $lista += @{ s = "trivy"; t = $TrivyImage; o = @{} }
    foreach ($c in $lista) {
        Say "   - $($a.name): $($c.s)"
        try {
            $created = Api Post "/agent-scans" @{ agent_id = $a.id; name = "prueba-$($c.s)"; scanner_type = $c.s; target = $c.t; options = $c.o; api_key = $a.bootstrap_api_key }
            $jid = $created.id
            $j = $created
            $t0 = Get-Date
            while ($j.status -notin @("completed", "failed") -and ((Get-Date) - $t0).TotalSeconds -lt $TimeoutSeg) {
                Start-Sleep -Seconds 4
                $j = (@(ApiList "/agent-scans") | Where-Object { $_.id -eq $jid } | Select-Object -First 1)
            }
            Cerrar $g $c.s $j @("completed")
        } catch { Add-Row $g $c.s "FALLA" "-" $_.Exception.Message }
    }
}

} catch { Add-Row "agentes" "-" "FALLA" "-" $_.Exception.Message }

# ---------- resumen ----------
Say "`n================ RESULTADO ================" Cyan
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
$fallas = @($rows | Where-Object { $_.Estado -in @("FALLA", "TIMEOUT") }).Count
if ($fallas -eq 0) { Say "TODO OK: los scanners funcionan de punta a punta." Green }
else { Say "$fallas prueba(s) con problema. Mandame esta tabla y lo corrijo." Yellow }
