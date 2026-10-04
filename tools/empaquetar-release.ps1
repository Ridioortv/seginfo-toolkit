<#
Arma el paquete de venta de SentinelOps (carpeta limpia + .zip) a partir de lo
COMMITEADO en git -- asi nunca se cuela un .env, un log, la carpeta de otro
proyecto ni el licensing-server (que tiene tus claves privadas).

Uso (desde la raiz del repo, en PowerShell):
    .\tools\empaquetar-release.ps1 -Version 1.0.0
    .\tools\empaquetar-release.ps1 -Version 1.0.0 -IncluirBinariosLAN

El .zip queda en release\SentinelOps-<version>.zip. Si lo queres en .rar,
abri la carpeta release\SentinelOps-<version>\ con WinRAR y comprimila.
-IncluirBinariosLAN suma remote-agent\bin\*.exe (nuclei/trivy/gitleaks, ~340MB)
al paquete; sin ese flag el cliente los baja por su cuenta.
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$IncluirBinariosLAN
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

# 1) El paquete sale de lo commiteado: avisar si hay cambios sin commitear.
$sucio = git status --porcelain --untracked-files=no
if ($sucio) { Write-Warning "Hay cambios sin commitear -- NO van en el paquete:`n$sucio" }

$destino = "release\SentinelOps-$Version"
if (Test-Path $destino) { Remove-Item $destino -Recurse -Force }
New-Item -ItemType Directory -Path $destino | Out-Null

# 2) Exportar solo archivos trackeados, sin lo interno/privado.
$tar = "release\_tmp.tar"
git archive --format=tar -o $tar HEAD -- . `
    ':(exclude)licensing-server' ':(exclude)STATUS.md' ':(exclude).github' `
    ':(exclude)render.yaml' ':(exclude)tools'
tar -xf $tar -C $destino
Remove-Item $tar

# 3) Los launchers .exe estan en .gitignore pero son parte del producto.
foreach ($exe in "SentinelOps - Iniciar.exe", "SentinelOps - Detener.exe") {
    if (Test-Path $exe) { Copy-Item $exe $destino }
}
if ($IncluirBinariosLAN -and (Test-Path "remote-agent\bin")) {
    New-Item -ItemType Directory -Path "$destino\remote-agent\bin" -Force | Out-Null
    Copy-Item "remote-agent\bin\*.exe" "$destino\remote-agent\bin\"
}

# 4) Verificaciones de seguridad y licencias antes de zipear.
$falta = @("LICENSE", "THIRD-PARTY-LICENSES.md", "THIRD-PARTY-DEPENDENCIES.md",
           "licenses\SEMGREP-LGPL-SOURCE-OFFER.txt", "licenses\APACHE-2.0.txt", "licenses\LGPL-2.1.txt") |
    Where-Object { -not (Test-Path "$destino\$_") }
if ($falta) { throw "Faltan archivos de licencia en el paquete: $($falta -join ', ')" }
$prohibidos = Get-ChildItem $destino -Recurse -Force -File |
    Where-Object { $_.Name -in ".env", "agente-lan.log" -or $_.FullName -match "licensing-server|sentinel para sofi" }
if ($prohibidos) { throw "El paquete contiene archivos que no deben salir: $($prohibidos.FullName -join ', ')" }

# 5) Zip.
$zip = "release\SentinelOps-$Version.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "$destino\*" -DestinationPath $zip
"Listo: $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB)"
