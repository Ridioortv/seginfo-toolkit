<#
.SYNOPSIS
  Copia las plantillas de tools\github-templates a .github\ (workflows de CI y
  seguridad, Dependabot, CODEOWNERS y plantilla de PR).
.DESCRIPTION
  La carpeta .github esta protegida contra escritura automatica, asi que este
  paso lo haces vos. Si ya existe un archivo distinto, guarda una copia .bak
  (ignorada por git) antes de reemplazarlo.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\aplicar-github.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $PSScriptRoot 'github-templates'
$map = @{
    'ci.yml'                    = '.github\workflows\ci.yml'
    'security.yml'              = '.github\workflows\security.yml'
    'dependabot.yml'            = '.github\dependabot.yml'
    'CODEOWNERS'                = '.github\CODEOWNERS'
    'pull_request_template.md'  = '.github\pull_request_template.md'
}
foreach ($name in $map.Keys) {
    $from = Join-Path $src $name
    $to = Join-Path $root $map[$name]
    if (-not (Test-Path -LiteralPath $from)) { Write-Warning "Falta $name en github-templates"; continue }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to) | Out-Null
    if ((Test-Path -LiteralPath $to) -and ((Get-FileHash $from).Hash -ne (Get-FileHash $to).Hash)) {
        Copy-Item -LiteralPath $to -Destination "$to.bak" -Force
    }
    Copy-Item -LiteralPath $from -Destination $to -Force
    Write-Host "OK  $($map[$name])" -ForegroundColor Green
}
Write-Host "Listo. Revisa con 'git status' y commitea .github\ junto con el resto." -ForegroundColor Cyan
