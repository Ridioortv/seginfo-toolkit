# Agente de escaneo remoto de SentinelOps

## Que problema resuelve

`scan-service` corre dentro de un contenedor Docker. En Docker Desktop
(Windows/Mac) los contenedores quedan aislados detras de NAT: no ven la
LAN real de la oficina o del cliente, aunque Docker Desktop este
instalado en una PC de esa misma red. Por eso un escaneo con nuclei o
trivy contra un target de esa LAN lanzado desde la UI de SentinelOps no
encuentra nada, aunque esa red exista y sea escaneable desde la propia
PC "por fuera" de Docker.

Este agente es un script chico que corre **fuera** de Docker -- en la
misma PC donde esta instalado SentinelOps, o en cualquier otra maquina
de esa LAN con visibilidad real a la red que se quiere escanear -- y
hace de "brazos y piernas" para los escaneos que scan-service no puede
alcanzar el mismo.

Soporta los mismos **8 scanners** que scan-service: `nuclei`, `trivy`,
`zap` (OWASP ZAP), `semgrep`, `gitleaks`, `yara`, `zeek` y `falco`. Una
salvedad: **`zeek` y `falco` necesitan captura de paquetes / eBPF de
Linux y NO corren en el Agente LAN nativo de Windows** (`agente-lan.ps1`)
-- si se les asigna un job de zeek/falco, lo rechazan al toque con un
mensaje claro. Para esos dos usa el Agente Docker (corre Linux dentro
del contenedor, que ya trae los permisos de kernel necesarios).

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
- El agente **solo sabe correr en modo no intrusivo**: `nuclei` sin las
  categorias de templates `dos`/`fuzz`/`intrusive`; `trivy` solo lee;
  `zap` solo en modo pasivo (spider + analisis pasivo, nunca
  `-quickattack`/escaneo activo); `semgrep`/`gitleaks`/`yara` solo LEEN
  codigo/archivos (nunca ejecutan nada del repo/target escaneado); y
  `zeek`/`falco` solo observan trafico/eventos durante una ventana de
  tiempo fija (`options.duration_minutes`, 1-60 min, default 5). Es
  exactamente el mismo comando (y las mismas restricciones) que usa
  `scan-service` cuando escanea el mismo desde adentro del contenedor.
- **`semgrep` y `yara` usan UNICAMENTE reglas propias de SentinelOps**
  (`backend/services/scan-service/rules/semgrep/sentinelops-rules.yml` y
  `.../rules/yara/sentinelops.yar`), nunca el registro publico de
  semgrep (`--config auto`/`p/...`) ni packs de YARA de terceros -- una
  decision de licenciamiento (ver `THIRD-PARTY-LICENSES.md` en la raiz
  del repo), no solo tecnica.

## Requisitos

- Python 3.9 o mas nuevo. El script **no usa ninguna libreria externa**
  -- solo la libreria estandar de Python -- asi que no hace falta
  `pip install` nada.
- El agente corre 8 scanners posibles (se elige por job, campo
  `scanner_type`). Solo hace falta instalar el/los binarios de los que
  vayas a usar en la maquina del agente -- si falta uno, ese job vuelve
  con un mensaje de error claro en vez de colgarse; el resto sigue
  funcionando igual:
  - **trivy** (CVEs en imagenes/paquetes): instalar el binario `trivy`
    (ver [aquasecurity/trivy](https://github.com/aquasecurity/trivy)) y
    dejarlo en el `PATH`. Baja su propia base de CVEs la primera vez que
    corre (puede tardar unos minutos ese primer escaneo).
  - **nuclei** (deteccion por plantillas): instalar el binario `nuclei`
    (ver [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei))
    y dejarlo en el `PATH`. El agente refresca las templates solo al
    arrancar y despues cada 12hs en segundo plano -- no hace falta correr
    `nuclei -update-templates` a mano.
  - **zap** (OWASP ZAP, DAST pasivo contra una URL): instalar
    [OWASP ZAP](https://www.zaproxy.org/download/) y dejar `zap`/`zap.bat`
    en el `PATH`. El target tiene que ser una URL `http://`/`https://`.
  - **semgrep** (SAST, motor LGPL-2.1): `pip install semgrep` (o ver
    [semgrep.dev/docs/getting-started](https://semgrep.dev/docs/getting-started))
    y dejarlo en el `PATH`. El target puede ser una URL git clonable
    (`http(s)://...git`) o un path local ya existente en la maquina del
    agente. Usa SIEMPRE las reglas propias del repo
    (`SENTINELOPS_SEMGREP_RULES_DIR`, default
    `backend/services/scan-service/rules/semgrep/` relativo a la raiz del
    repo) -- nunca el registro publico de semgrep.
  - **gitleaks** (secretos en un repo/path, MIT): instalar el binario
    `gitleaks` (ver [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks#installing))
    y dejarlo en el `PATH`. Mismo target que semgrep (URL git o path
    local). **Ya viene listo en `remote-agent/bin/gitleaks.exe`**
    (binario oficial de la release de GitHub) -- no hace falta instalar
    nada para este.
  - **yara** (patrones/indicadores conocidos en archivos, BSD-3-Clause):
    instalar el binario `yara` (ver
    [VirusTotal/yara](https://virustotal.github.io/yara/)) y dejarlo en
    el `PATH`. El target tiene que ser un path local (archivo o carpeta)
    ya existente en la maquina del agente. Usa SIEMPRE las reglas
    propias del repo (`SENTINELOPS_YARA_RULES_FILE`, default
    `backend/services/scan-service/rules/yara/sentinelops.yar`).
    **Ojo en Windows**: el proyecto YARA no publica un `yara.exe`
    precompilado en sus releases de GitHub (solo codigo fuente) --
    para usarlo desde el Agente LAN hay que compilarlo a mano
    (ver la guia de compilacion en el link de arriba) o instalarlo via
    un gestor de paquetes como Chocolatey (`choco install yara`) o
    vcpkg, y despues poner ese `.exe` en el `PATH` o en
    `remote-agent/bin/yara.exe`. Mientras tanto ese job va a fallar con
    un mensaje claro en vez de romper el agente.
  - **zeek** y **falco**: **no soportados en el Agente LAN nativo de
    Windows** -- necesitan captura de paquetes / eBPF de Linux. Usa el
    Agente Docker para estos dos (ver "Produccion" mas abajo).

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
remotos", elegi el agente registrado, el scanner (`nuclei`, `trivy`,
`zap`, `semgrep`, `gitleaks`, `yara`, `zeek` o `falco`) y el target, y
crea el job (para `zeek`/`falco` tambien elegis la duracion en minutos,
1-60). El agente lo va a recoger en su siguiente poll (dentro de
`POLL_INTERVAL_SECONDS`), correr el scanner elegido, y mandar los
resultados de vuelta -- los vas a ver aparecer en esa misma pagina, y los
hallazgos se reenvian automaticamente a vuln-service para priorizacion
(CVSS/EPSS/KEV), igual que un escaneo normal.

## Si algo no funciona

- **"api key rechazada por scan-service (401)"**: revisa que
  `AGENT_API_KEY` este bien copiada (sin espacios de mas) y que el
  agente no haya sido borrado desde la UI.
- **"no se pudo conectar a scan-service"**: revisa `SCAN_SERVICE_URL` --
  si el agente corre en otra maquina, `localhost` no va a funcionar,
  necesitas la IP de la LAN de la PC donde esta SentinelOps, y que el
  firewall de esa PC permita conexiones entrantes al puerto 8003 desde
  esa otra maquina.
- **Los jobs quedan en "failed" con "<scanner> no esta instalado o no
  esta en el PATH"**: instala el binario que falta (ver Requisitos
  arriba) y asegurate de poder correrlo desde la misma terminal donde
  corres `agent.py` (o donde corre `agente-lan.ps1`).
- **Un job de "zeek" o "falco" vuelve rechazado con "requiere el Agente
  Docker"**: es esperado si se lo asignaste al Agente LAN -- esos dos
  scanners necesitan captura de paquetes/eBPF de Linux, asignalos al
  Agente Docker en cambio.
- **El escaneo tarda mucho o falla por timeout**: el agente usa los
  mismos timeouts que scan-service -- si necesitas escanear muchos
  targets, es mejor dividir en varios jobs mas chicos.
- **Los jobs quedan "pending"/"assigned" mucho tiempo usando el Agente
  Docker contra una IP de LAN (192.168.x.x, 10.x.x.x)**: el Agente
  Docker corre DENTRO de Docker Desktop, detras de su NAT, y ni trivy
  ni nuclei tienen forma de atravesarlo -- con
  `AGENT_BEHIND_DOCKER_NAT=1` (ya seteado para el Agente Docker en
  `docker-compose.yml`) esos jobs fallan al toque con un mensaje claro
  en vez de quedarse varios minutos intentando conectar.
  **El Agente LAN (`agente-lan.ps1`) SI puede correr nuclei y trivy
  contra la LAN**, pero no de cero: si encuentra `nuclei.exe`/`trivy.exe`
  instalados (en el PATH, o en remote-agent\bin\) en la PC donde corre, los usa de verdad, con
  los mismos flags/restricciones que el driver in-container (solo
  deteccion, nunca explotacion activa). Si no los encuentra, ese job
  vuelve con un mensaje claro que dice que instalar -- y el PROXIMO job
  ya funciona, sin reiniciar el agente (se chequea en cada job, no solo
  al arrancar).
- **Varios jobs asignados a la vez, uno lento no debería trabar a los
  demas**: el agente los corre en threads separados (hasta
  `AGENT_MAX_CONCURRENT_JOBS`, default 8) -- un escaneo que tarda varios
  minutos no bloquea que otro mas rapido, asignado en el mismo poll, se
  resuelva enseguida.

---

## Produccion: agentes que se crean y arrancan solos

Ya no hace falta registrar el agente a mano ni correr comandos sueltos.
scan-service **auto-registra** los agentes definidos en `BOOTSTRAP_AGENTS`
(en `.env`) al arrancar -- es idempotente, reiniciar no duplica nada. Por
defecto se crean tres:

- **Agente WAN (internet)** -> corre como el contenedor `remote-agent-wan`
  dentro del stack (misma imagen que scan-service). Escanea **solo
  objetivos publicos de internet**: rechaza al toque cualquier IP privada o
  interna (`192.168.x.x`, `10.x.x.x`, `localhost`, `host.docker.internal`,
  `*.local`...) con un mensaje que manda al Agente LAN, y no corre
  `zeek`/`falco`/`yara` (analizan el propio equipo o archivos locales, no
  internet). Corre sin las capabilities elevadas de zeek/falco (minimo
  privilegio). Se activa con `AGENT_ROLE=wan` (ver `docker-compose.yml`).
- **Agente Docker (internet/host)** -> corre como el contenedor
  `remote-agent` dentro del stack (misma imagen que scan-service, ya trae
  los 8 scanners -- trivy/nuclei/zap/semgrep/gitleaks/yara/zeek/falco --
  y las reglas propias de semgrep/yara horneadas adentro). Arranca solo
  con `docker compose up`. Por el NAT de Docker Desktop escanea internet
  y la propia PC (`host.docker.internal`), **no** la LAN -- pero es el
  unico que puede correr `zeek`/`falco` (necesitan Linux).
- **Agente LAN** -> corre en el **host** (fuera de Docker) para llegar a la
  red real (`192.168.x.x`). Es un script PowerShell nativo
  (`remote-agent/agente-lan.ps1`) que **no requiere instalar Python ni
  nada mas**: usa PowerShell + .NET puro, que ya vienen con Windows.
  Para nuclei/trivy/zap/semgrep/gitleaks/yara busca el binario en dos
  lugares, en este orden: el PATH del sistema, y despues
  `remote-agent/bin/<nombre>.exe` (o `.bat` para `zap`) -- una carpeta al
  lado del script (creala si no existe) donde alcanza con poner el .exe
  descargado oficialmente, sin instalar nada de verdad ni tocar el PATH
  de Windows. Cualquiera de los dos lugares funciona, y el agente los
  detecta en el siguiente job sin reiniciarse. Esa carpeta
  (`remote-agent/bin/`) esta en `.gitignore` (via `*.exe`) -- esos
  binarios NUNCA se commitean (GitHub bloquea archivos de mas de 100MB,
  y varios de estos pesan bastante). `zeek` y `falco` quedan afuera de
  este agente -- ver la salvedad al principio de este README.

Las api keys de los tres estan en `.env` (`REMOTE_AGENT_DOCKER_KEY`,
`REMOTE_AGENT_LAN_KEY` y `REMOTE_AGENT_WAN_KEY`) -- son las que se pegan en
la UI al lanzar un escaneo remoto (o se autocompletan solas si elegis uno de
estos agentes bootstrap, ver la tabla de agentes en `/scans`). Cambialas por
valores propios en un despliegue real. Si sacas un agente de
`BOOTSTRAP_AGENTS`, scan-service lo borra solo (con sus escaneos remotos) en
el siguiente arranque.

### Instalar el Agente LAN (un solo paso, sin ser administrador)

Antes habia que registrar una tarea de Windows a mano con `schtasks` y
editar la ruta del repo en el comando. Ahora alcanza con doble-clic en
**`Instalar-Agente-LAN.bat`** (dentro de `remote-agent/`), una sola vez:
deja el Agente LAN corriendo en segundo plano YA MISMO, y ademas
registrado para que arranque solo en cada inicio de sesion de Windows de
ahi en adelante -- nunca mas hay que abrir nada a mano, ni dejar ninguna
ventana abierta, ni en tu PC ni en la de un cliente.

Bajo el capot, `Instalar-Agente-LAN.bat` corre
`agente-lan.ps1 -Install`, que usa el modulo `ScheduledTasks` que ya
trae Windows 10/11 (no instala nada nuevo) para registrar la tarea con
tu propio usuario -- no hace falta ser administrador. Otros comandos
utiles (desde `remote-agent/`, en PowerShell):

```powershell
.gente-lan.ps1 -Status      # esta instalado? corriendo? ver el log
.gente-lan.ps1 -Uninstall   # sacarlo de los programas de inicio
```

El log queda en `remote-agent/agente-lan.log` -- util para revisar que
paso si la tabla de agentes en `/scans` no muestra a "Agente LAN" con
una fecha reciente en "Ultima vez visto".

Para correrlo a mano, en una ventana visible (por ejemplo para probarlo
una vez o mirarlo en vivo), doble-clic en `Iniciar-Agente-LAN.bat` en
cambio -- se detiene si cerras esa ventana.

### Probar todo el pipeline sin escanear nada real

`python remote-agent/test_pipeline.py` (ver cabecera del archivo) ejercita
el ciclo completo para los 8 scanners y valida la seguridad de la api key.
