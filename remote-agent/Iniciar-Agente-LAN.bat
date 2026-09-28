@echo off
REM Doble-clic para arrancar el Agente LAN de SentinelOps (escaneo de la red real).
REM Deja esta ventana abierta mientras quieras que el agente trabaje.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0agente-lan.ps1"
echo.
echo El agente se detuvo. Podes cerrar esta ventana.
pause
