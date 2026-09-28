@echo off
REM Doble-clic para arrancar el Agente LAN de SentinelOps EN ESTA VENTANA
REM (para probarlo una vez o ver en vivo que esta haciendo). Se detiene si
REM cerras esta ventana. Para dejarlo instalado y que arranque solo con
REM Windows, sin tener que abrir nada de nuevo, usa en cambio
REM Instalar-Agente-LAN.bat (una sola vez).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0agente-lan.ps1"
echo.
echo El agente se detuvo. Podes cerrar esta ventana.
pause
