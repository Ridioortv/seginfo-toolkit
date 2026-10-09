<#
.SYNOPSIS
  Activa en GitHub las protecciones de seguridad del repositorio (idempotente).

.DESCRIPTION
  Usa la CLI oficial `gh` con TU sesion (gh auth login). No guarda ni imprime tokens.
  Activa: secret scanning + push protection, alertas y parches automaticos de
  Dependabot, reporte privado de vulnerabilidades, permisos de solo lectura por
  defecto para GitHub Actions y proteccion de la rama main (sin force-push, sin
  borrado, conversaciones resueltas). Cada paso informa OK o AVISO sin abortar:
  algunas funciones dependen del plan (p. ej. secret scanning en repos privados
  requiere GitHub Advanced Security).

.PARAMETER Repo
  owner/nombre. Por defecto, el del remote 'origin'.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\github-blindaje.ps1
#>
[CmdletBinding()]
param([string]$Repo)

$ErrorActionPreference = 'Continue'

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "Falta la CLI de GitHub. Instalala (winget install GitHub.cli), corre 'gh auth login' y reintenta." -ForegroundColor Yellow
    exit 1
}
gh auth status *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "No hay sesion de gh. Corre 'gh auth login' (navegador) y reintenta." -ForegroundColor Yellow
    exit 1
}

if (-not $Repo) {
    $url = (git remote get-url origin 2>$null)
    if ($url -match 'github\.com[:/]+([^/]+/[^/.]+?)(\.git)?$') { $Repo = $Matches[1] }
}
if (-not $Repo) { Write-Host "No pude deducir el repo. Usa -Repo owner/nombre." -ForegroundColor Yellow; exit 1 }
Write-Host "Repositorio: $Repo" -ForegroundColor Cyan

function Invoke-Paso([string]$Nombre, [string]$Metodo, [string]$Ruta, [string]$Json) {
    if ($Json) { $out = $Json | gh api -X $Metodo $Ruta --input - 2>&1 }
    else       { $out = gh api -X $Metodo $Ruta 2>&1 }
    if ($LASTEXITCODE -eq 0) { Write-Host ("  OK     {0}" -f $Nombre) -ForegroundColor Green }
    else {
        $msg = ($out | Out-String).Trim() -replace '\s+', ' '
        if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) + '...' }
        Write-Host ("  AVISO  {0}: {1}" -f $Nombre, $msg) -ForegroundColor Yellow
    }
}

$info = gh api "repos/$Repo" 2>$null | ConvertFrom-Json
if ($info) {
    $vis = if ($info.private) { 'PRIVADO' } else { 'PUBLICO' }
    Write-Host "Visibilidad: $vis | rama por defecto: $($info.default_branch)"
    $branch = $info.default_branch
} else { $branch = 'main' }

Write-Host "`nProtecciones de contenido y dependencias:" -ForegroundColor Cyan
Invoke-Paso 'Secret scanning + push protection' 'PATCH' "repos/$Repo" '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}'
Invoke-Paso 'Alertas de Dependabot' 'PUT' "repos/$Repo/vulnerability-alerts" ''
Invoke-Paso 'Parches de seguridad automaticos (Dependabot)' 'PUT' "repos/$Repo/automated-security-fixes" ''
Invoke-Paso 'Reporte privado de vulnerabilidades' 'PUT' "repos/$Repo/private-vulnerability-reporting" ''

Write-Host "`nGitHub Actions:" -ForegroundColor Cyan
Invoke-Paso 'GITHUB_TOKEN de solo lectura por defecto' 'PUT' "repos/$Repo/actions/permissions/workflow" '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'

Write-Host "`nProteccion de la rama '$branch':" -ForegroundColor Cyan
$prot = '{"required_status_checks":null,"enforce_admins":false,"required_pull_request_reviews":null,"restrictions":null,"allow_force_pushes":false,"allow_deletions":false,"required_conversation_resolution":true}'
Invoke-Paso "Sin force-push ni borrado de '$branch'" 'PUT' "repos/$Repo/branches/$branch/protection" $prot

Write-Host "`nRamas remotas (revisa si sobra alguna de prueba):" -ForegroundColor Cyan
gh api "repos/$Repo/branches" --jq '.[].name' 2>$null | ForEach-Object { Write-Host "  - $_" }
Write-Host "  Para borrar una rama de prueba:  git push origin --delete <nombre>"

Write-Host "`nTe falta hacer a mano (no se puede automatizar sin tu cuenta web):" -ForegroundColor Cyan
Write-Host "  1) REVOCAR el token que estuvo en .git/config:  https://github.com/settings/tokens  y  https://github.com/settings/personal-access-tokens"
Write-Host "  2) Activar 2FA (llave de seguridad o app) en https://github.com/settings/security"
Write-Host "  3) Cuando el CI este estable: en Settings > Branches exigi los checks 'Security' y 'CI' y revision de CODEOWNERS."
Write-Host "  4) Para el push desde esta PC usa Git Credential Manager o un token fine-grained SOLO de este repo (Contents: read/write), nunca en la URL del remote."
