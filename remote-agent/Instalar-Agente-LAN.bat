@echo off
REM Doble-clic UNA SOLA VEZ: deja el Agente LAN de SentinelOps instalado
REM para que arranque solo cada vez que inicies sesion en Windows -- no
REM hace falta volver a abrir nada, ni dejar ninguna ventana abierta.
REM No requiere ser administrador.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0agente-lan.ps1" -Install
echo.
pause
