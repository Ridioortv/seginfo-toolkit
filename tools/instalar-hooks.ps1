<#
.SYNOPSIS
  Activa el hook pre-commit anti-secretos de este repositorio.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\instalar-hooks.ps1
#>
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
git config core.hooksPath .githooks
try { git update-index --chmod=+x .githooks/pre-commit 2>$null } catch { }
Write-Host "Hook pre-commit activado (core.hooksPath = .githooks)." -ForegroundColor Green
Write-Host "Frena commits con .env, claves privadas y tokens conocidos. Opcional: instala gitleaks para un chequeo mas profundo."
