<#
Arma el archivo para instalar TERO Security SIN internet:  tero-imagenes-<version>.tar.zst  (+ .sha256)

Se corre en una PC CON internet (y con "docker login ghcr.io" hecho). Junta todas las imagenes de
Docker de esta version en un solo archivo. Para instalar en la PC sin internet: copiar ESE archivo
(y el .sha256) a la carpeta de TERO Security (junto a "TERO Security - Iniciar.exe") y abrir el
programa como siempre: lo detecta, verifica que este completo, hace `docker load` y no baja nada.

Uso (PowerShell, desde la raiz del repo o del paquete):
    .\tools\empaquetar-offline.ps1                 # baja las imagenes de GHCR y las empaqueta
    .\tools\empaquetar-offline.ps1 -Compilar       # las compila aca (en tandas de 3) en vez de bajarlas
    .\tools\empaquetar-offline.ps1 -Salida D:\     # donde dejar el archivo (default: carpeta de arriba)

Necesita zstd (https://github.com/facebook/zstd/releases) en el PATH. El archivo es el MISMO que arma
./empaquetar-offline.sh en Linux: sirve para las dos versiones.
#>
param(
    [switch]$Compilar,
    [string]$Salida = ""
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not $Salida) { $Salida = (Resolve-Path "..").Path }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker no esta instalado." }
if (-not (Get-Command zstd -ErrorAction SilentlyContinue)) { throw "Falta zstd. Descargalo de https://github.com/facebook/zstd/releases y ponelo en el PATH." }

$version = (Get-Content VERSION -Raw).Trim()
$env:TERO_VERSION = $version
$archivo = Join-Path $Salida "tero-imagenes-$version.tar.zst"
$parcial = "$archivo.parcial"

# compose necesita un .env para resolver variables; si no hay, uno temporal de ejemplo (no entra al archivo).
$envTemporal = $false
if (-not (Test-Path .env)) { Copy-Item .env.example .env; $envTemporal = $true }
try {
    if ($Compilar) {
        $env:BUILDX_NO_DEFAULT_ATTESTATIONS = "1"
        $env:COMPOSE_PARALLEL_LIMIT = "3"
        $f = @("-f", "docker-compose.yml", "-f", "docker-compose.dev.yml")
        docker compose @f --profile build build tero-base
        if ($LASTEXITCODE) { throw "Fallo la imagen base." }
        $servicios = Select-String -Path docker-compose.dev.yml -Pattern '^  ([a-z][a-z0-9-]*):\s*$' |
            ForEach-Object { $_.Matches[0].Groups[1].Value } |
            Where-Object { $_ -notin "tero-base", "remote-agent", "remote-agent-wan" }
        for ($i = 0; $i -lt $servicios.Count; $i += 3) {
            $tanda = $servicios[$i..([Math]::Min($i + 2, $servicios.Count - 1))]
            Write-Host "Compilando: $($tanda -join ' ')"
            docker compose @f build @tanda
            if ($LASTEXITCODE) { throw "Fallo la compilacion de: $($tanda -join ', ')" }
        }
        docker compose pull postgres redis opensearch   # imagenes publicas: no se compilan
        if ($LASTEXITCODE) { throw "No pude bajar postgres/redis/opensearch." }
    } else {
        docker compose pull
        if ($LASTEXITCODE) { throw "No pude bajar las imagenes (te falta 'docker login ghcr.io' o la conexion)." }
    }

    $imagenes = docker compose config --images | Sort-Object -Unique
    if (-not $imagenes) { throw "No pude leer la lista de imagenes del compose." }
    foreach ($img in $imagenes) {
        docker image inspect $img *> $null
        if ($LASTEXITCODE) { throw "Falta la imagen $img en esta PC." }
    }

    Write-Host "Empaquetando $($imagenes.Count) imagenes en $archivo (tarda varios minutos)..."
    # cmd /c para que el pipe sea binario (el de PowerShell corrompe los bytes).
    cmd /c "docker save $($imagenes -join ' ') | zstd -T0 -10 -q -f -o `"$parcial`""
    if ($LASTEXITCODE) { Remove-Item $parcial -ErrorAction SilentlyContinue; throw "Fallo al guardar las imagenes." }
    zstd -t -q $parcial
    if ($LASTEXITCODE) { Remove-Item $parcial -ErrorAction SilentlyContinue; throw "El archivo generado esta danado. Volve a intentarlo." }
    Move-Item $parcial $archivo -Force
    $hash = (Get-FileHash $archivo -Algorithm SHA256).Hash.ToLower()
    Set-Content -Path "$archivo.sha256" -Value "$hash  $(Split-Path $archivo -Leaf)" -Encoding ascii
    "Listo: $archivo ($([math]::Round((Get-Item $archivo).Length / 1GB, 2)) GB)"
} finally {
    if ($envTemporal) { Remove-Item .env -ErrorAction SilentlyContinue }
}
