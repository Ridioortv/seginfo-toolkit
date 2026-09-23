# Agente de escaneo remoto de SentinelOps

## Que problema resuelve

`scan-service` corre dentro de un contenedor Docker. En Docker Desktop
(Windows/Mac) los contenedores quedan aislados detras de NAT: no ven la
LAN real de la oficina o del cliente, aunque Docker Desktop este
instalado en una PC de esa misma red. Por eso un escaneo nmap contra un
rango tipo `192.168.1.0/24` lanzado desde la UI de SentinelOps no
encuentra nada, aunque esa red exista y sea escaneable desde la propia
PC "por fuera" de Docker.

Este agente es un script Python chico que corre **fuera** de Docker
-- en la misma PC donde esta instalado SentinelOps, o en cualquier otra
maquina de esa LAN con visibilidad real a la red que se quiere
escanear -- y hace de "brazos y piernas" para los escaneos que scan-
service no puede alcanzar el mismo.

## Como funciona (modelo de seguridad)

- El agente **siempre inicia la conexion** hacia `scan-service`
  (polling periodico). Nunca es al reves. Por eso **no hace falta abrir
  ningun puerto de entrada** en la red de la oficina/cliente: alcanza
  con que la maquina del agente pueda llegar, de salida, al puerto que
  `scan-service` ya publica (`8003` por defecto, ver
  `docker-compose.yml`).
- No hay ningun servidor "relay" en internet ni endpoint publico
  involucrado. El uso tipico de SentinelOps es on-prem/self-hosted en la
  red del propio cliente, asi que el agente solo necesita llegar al
  `scan-service` de esa misma instalacion (via `localhost` si esta en la
  misma PC, o via la IP de la LAN si esta en otra maquina).
- El agente se autentica con una **api key propia** (nunca con el
  usuario/contraseña ni el JWT de una persona), enviada en el header
  `X-Agent-Key` en cada request. `scan-service` solo guarda el **hash**
  (sha256) de esa key -- la key en texto plano se muestra una unica vez,
  en el momento de registrar el agente desde la UI, y despues no se
  puede volver a ver (si se pierde, hay que borrar el agente y crear uno
  nuevo).
- El agente **solo sabe correr nmap en modo deteccion**: descubrimiento
  de puertos/servicios (`-sV`) mas scripts de deteccion segura
  (`-sC --script default,safe`). Nunca ejecuta `--script vuln` ni
  scripts de las categorias `exploit`/`intrusive` -- es exactamente el
  mismo comando (y las mismas restricciones) que usa `scan-service`
  cuando escanea el mismo desde adentro del contenedor.

## Requisitos

- Python 3.9 o mas nuevo. El script **no usa ninguna libreria externa**
  -- solo la libreria estandar de Python -- asi que no hace falta
  `pip install` nada.
- `nmap` instalado y disponible en el `PATH` de la maquina donde va a
  correr el agente:
  - **Windows**: instalar [Nmap para Windows](https://nmap.org/download.html#windows)
    y dejar tildada la opcion de instalar **Npcap** durante la
    instalacion (nmap lo necesita para varias de sus tecnicas de
    deteccion en Windows).
  - **Linux**: `sudo apt install nmap` (Debian/Ubuntu) o el equivalente
    de tu distro.
  - **macOS**: `brew install nmap`.

## Paso 1: registrar el agente en SentinelOps

1. Entra a la pagina **Escaneos** de SentinelOps (necesitas rol
   `admin`).
2. En el panel "Agentes de escaneo remoto", clickea "Registrar agente"
   y ponele un nombre descriptivo (ej. `PC-oficina-recepcion` o
   `notebook-consultor-onsite`).
3. La UI te va a mostrar una **api key** -- copiala en ese momento, es
   la unica vez que se muestra. Guardala en un lugar seguro (un gestor
   de contraseñas, por ejemplo) hasta que la configures en el paso 2.

## Paso 2: configurar y correr el agente

El script se configura con variables de entorno:

| Variable | Default | Descripcion |
|---|---|---|
| `AGENT_API_KEY` | *(requerida)* | La api key del paso 1. |
| `SCAN_SERVICE_URL` | `http://localhost:8003` | URL de `scan-service`. Si el agente corre en la MISMA PC que SentinelOps, el default alcanza. Si corre en OTRA maquina de la LAN, usa la IP de la PC donde esta SentinelOps, ej. `http://192.168.1.50:8003`. |
| `POLL_INTERVAL_SECONDS` | `10` | Cada cuanto pregunta si hay escaneos nuevos asignados. |

### Windows (símbolo de sistema / cmd)

```bat
set AGENT_API_KEY=la-key-que-copiaste-en-el-paso-1
set SCAN_SERVICE_URL=http://localhost:8003
python agent.py
```

### Windows (PowerShell)

```powershell
$env:AGENT_API_KEY = "la-key-que-copiaste-en-el-paso-1"
$env:SCAN_SERVICE_URL = "http://localhost:8003"
python agent.py
```

### Linux / macOS

```bash
export AGENT_API_KEY="la-key-que-copiaste-en-el-paso-1"
export SCAN_SERVICE_URL="http://localhost:8003"
python3 agent.py
```

Si todo esta bien configurado vas a ver algo como:

```
[agent] SentinelOps - agente de escaneo remoto iniciado.
[agent]   scan-service: http://localhost:8003
[agent]   intervalo de polling: 10s
[agent] Esperando jobs asignados (Ctrl+C para detener)...
```

El agente queda corriendo en primer plano (Ctrl+C para detenerlo). Para
dejarlo corriendo de forma mas permanente en Windows, se puede armar una
tarea programada o un acceso directo en la carpeta de inicio; en
Linux/Mac, un servicio `systemd` o simplemente `nohup`/`screen`/`tmux`.

## Paso 3: lanzar escaneos remotos

Desde la pagina **Escaneos** de SentinelOps, en el panel "Escaneos
remotos", elegi el agente registrado y el target (host o rango CIDR de
la LAN que el agente si puede ver) y crea el job. El agente lo va a
recoger en su siguiente poll (dentro de `POLL_INTERVAL_SECONDS`), correr
nmap, y mandar los resultados de vuelta -- los vas a ver aparecer en esa
misma pagina, y los hallazgos se reenvian automaticamente a vuln-service
para priorizacion (CVSS/EPSS/KEV), igual que un escaneo normal.

## Si algo no funciona

- **"api key rechazada por scan-service (401)"**: revisa que
  `AGENT_API_KEY` este bien copiada (sin espacios de mas) y que el
  agente no haya sido borrado desde la UI.
- **"no se pudo conectar a scan-service"**: revisa `SCAN_SERVICE_URL` --
  si el agente corre en otra maquina, `localhost` no va a funcionar,
  necesitas la IP de la LAN de la PC donde esta SentinelOps, y que el
  firewall de esa PC permita conexiones entrantes al puerto 8003 desde
  esa otra maquina.
- **Los jobs quedan en "failed" con "nmap no esta instalado o no esta en
  el PATH"**: instala nmap (ver Requisitos arriba) y asegurate de poder
  correr `nmap --version` desde la misma terminal donde corres
  `agent.py`.
- **El escaneo tarda mucho o falla por timeout**: el agente usa los
  mismos timeouts que scan-service (180s por escaneo, 30s por host que
  no responde) -- si necesitas escanear rangos grandes, es mejor dividir
  en varios jobs mas chicos que un solo `/24` entero.
