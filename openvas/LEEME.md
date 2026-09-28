# OpenVAS / Greenbone — apagado por defecto

## ¿Por qué está apagado? (en fácil)

OpenVAS (el motor Greenbone/GVM) es el escáner de vulnerabilidades más
pesado del proyecto: son **~16 contenedores** extra que descargan **varios
GB de "feeds"** (bases de CVEs y tests) cada vez que se sincronizan. Eso:

- hace que el stack tarde muchísimo en levantar,
- se rompe seguido en el primer arranque (el contenedor `scap-data` queda
  "unhealthy" mientras baja los feeds y traba todo lo demás),
- ocupa mucho disco y CPU.

Como **nmap + nuclei + trivy ya cubren la mayor parte de un análisis**
(puertos/servicios, CVEs conocidos en red y web, y CVEs en
imágenes/paquetes), dejamos OpenVAS **apagado por defecto**. Así el
programa arranca rápido y estable. OpenVAS **no se borró**: queda
disponible para prenderlo cuando de verdad lo necesites.

## ¿Qué me pierdo con OpenVAS apagado?

Sólo el escáner **openvas** (escaneo profundo/autenticado con el feed
gigante de NVTs, tipo Nessus). Todo lo demás sigue igual. Si en la UI
elegís el scanner "openvas" estando apagado, el escaneo te devuelve un
mensaje claro diciendo que está apagado y cómo prenderlo (no se cuelga).

## Cuándo conviene prenderlo

Cuando un cliente pide un **assessment profundo y autenticado de cada
host** (parches de SO faltantes, configuraciones locales inseguras). Para
eso OpenVAS no tiene reemplazo directo entre los otros tres.

---

## Cómo PRENDERLO — paso a paso (PowerShell)

> Todo se corre desde la raíz del proyecto:
> `cd C:\Users\manue\Documents\seginfo-toolkit`

### Paso 1 — Encender el motor
```powershell
powershell -ExecutionPolicy Bypass -File openvas\Encender-OpenVAS.ps1
```
Esto levanta los ~16 contenedores de Greenbone (profile `openvas`).

### Paso 2 — Esperar a que sincronicen los feeds
La **primera vez** tarda **20–40 min** (baja los feeds de CVEs/NVTs).
Mirá el progreso con:
```powershell
docker compose --profile openvas ps
```
Esperá a que `scap-data`, `gvmd`, `notus-data` y `ospd-openvas` figuren
`healthy` / `Up`. (Las próximas veces es mucho más rápido, ya quedan en
disco.)

### Paso 3 — Configurar el usuario y conectar scan-service
```powershell
powershell -ExecutionPolicy Bypass -File openvas\Configurar-OpenVAS.ps1
```
Este script crea el usuario admin de GVM, guarda las credenciales en
`.env` (GVM_USER / GVM_PASSWORD / GVM_SOCKET_PATH) y reinicia scan-service
para que tome la conexión. Te muestra la contraseña generada al final.

### Paso 4 — Usarlo
En la UI → Escaneos → elegí scanner **openvas** y lanzá. Ya escanea con el
motor real.

---

## Cómo APAGARLO de nuevo
```powershell
powershell -ExecutionPolicy Bypass -File openvas\Apagar-OpenVAS.ps1
```
Detiene los contenedores de Greenbone (no borra los feeds ya
descargados). El resto del programa sigue funcionando normal.

## Notas
- Con OpenVAS apagado, levantás el programa como siempre
  (`docker compose up -d` o el `Iniciar.exe`): los contenedores de GVM
  **no** arrancan porque están en el profile `openvas`.
- Para prenderlos hace falta el flag `--profile openvas` (los scripts de
  esta carpeta ya lo incluyen).
