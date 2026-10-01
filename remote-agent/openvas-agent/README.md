# Agente OpenVAS

## Que problema resuelve

El stack principal de SentinelOps (`docker-compose.yml` en la raiz del
repo, perfil `openvas`) corre gvmd/ospd-openvas atras del NAT de Docker
Desktop (Windows/Mac) -- no ven la LAN real de la oficina/cliente, el
mismo motivo por el que existe `remote-agent/agente-lan.ps1` para nmap.
A diferencia de nmap (que tiene un escaner interno por `connect()` que SI
atraviesa ese NAT, ver `remote-agent/agent.py::_run_python_portscan`), el
motor OpenVAS/Greenbone arma sus propios paquetes de red (ICMP, ARP, raw
sockets) -- no hay forma de "tunelearlo" desde adentro de una VM de
Docker Desktop. Por eso, hoy, tanto el Agente LAN como el Agente Docker
rechazan de entrada cualquier job `openvas` contra un target de LAN (y el
Agente Docker tampoco tiene gvmd propio para targets de internet).

Esta carpeta resuelve eso empaquetando el MISMO stack GVM del proyecto
principal (gvmd + ospd-openvas + feeds de NVTs), pero solo, para
desplegar en una maquina **Linux** que SI tenga visibilidad de red real
hacia lo que se quiere escanear -- puede ser un servidor del cliente, una
VM, un mini-PC puesto en su oficina. Se registra como un agente MAS en
"Escaneos" -> "Agentes de escaneo remoto" de la UI -- convive con el
Agente LAN y el Agente Docker sin reemplazar a ninguno; el selector de
agente de cada escaneo decide a cual se manda cada job.

## Requisitos

- Una maquina **Linux** (fisica, VM, mini-PC) con Docker + Docker Compose
  v2, con red real hacia los targets que se quieren escanear. **No uses
  Docker Desktop para Windows/Mac aca** -- tendria el mismo problema de
  NAT que el stack principal (ver arriba); en Linux nativo, el bridge de
  Docker enruta normalmente hacia la LAN del host, sin esa capa extra de
  virtualizacion.
- ~8 GB de disco libre y conexion a internet (la sincronizacion inicial
  de feeds baja varios GB la primera vez).
- Que el `scan-service` del stack PRINCIPAL de SentinelOps sea alcanzable
  por red desde esta maquina -- misma LAN, VPN, o el puerto `8003`
  expuesto de alguna forma.

## Instalacion

### Paso 1 -- Levantar el motor GVM

```bash
cd remote-agent/openvas-agent
cp .env.example .env
docker compose up -d gvmd ospd-openvas openvasd openvas vulnerability-tests notus-data scap-data cert-bund-data dfn-cert-data data-objects report-formats gpg-data gvm-redis pg-gvm pg-gvm-migrator configure-openvas
```

(Se levanta todo menos `openvas-agent` a proposito -- ese necesita
`AGENT_API_KEY`, que todavia no tenemos, ver paso 3.)

Esto arranca gvmd + ospd-openvas + los contenedores de feed. La
**primera sincronizacion tarda 20-40 min** (baja varios GB de CVEs/NVTs).
Segui el progreso con:

```bash
docker compose ps
```

### Paso 2 -- Crear el usuario GVM

Cuando `gvmd`, `scap-data`, `notus-data` y `ospd-openvas` esten
`healthy`/`Up`:

```bash
chmod +x configurar-gvm.sh   # solo la primera vez
./configurar-gvm.sh
```

Esto crea el usuario `admin` de GVM y guarda `GVM_USER`/`GVM_PASSWORD`
en `.env` (equivalente en bash de `openvas/Configurar-OpenVAS.ps1`, que
hace lo mismo para el stack principal).

### Paso 3 -- Registrar el agente en SentinelOps

En la UI de SentinelOps (necesitas rol `admin`): **Escaneos** ->
**Agentes de escaneo remoto** -> **Registrar agente** -> ponele un
nombre descriptivo (ej. `Agente OpenVAS - oficina cliente`). Copia la
api key que te muestra -- se ve **una sola vez**.

Completa en `.env` (de esta carpeta):

```
SCAN_SERVICE_URL=http://<ip-del-servidor-principal>:8003
AGENT_API_KEY=<la-key-del-paso-anterior>
```

### Paso 4 -- Arrancar el agente

```bash
docker compose up -d openvas-agent
```

Listo. Desde la UI, al elegir el scanner `openvas` en "Escaneos remotos"
(o "Escaneos programados"), seleccioná este agente en el selector de
agente para que el escaneo se procese con el motor GVM de esta maquina.

## Notas

- Este bundle es completamente independiente del stack principal: su
  propia base de datos, sus propios feeds, sus propios volumenes -- no
  comparte nada con el `docker-compose.yml` de la raiz salvo la conexion
  de red saliente hacia `scan-service` (`SCAN_SERVICE_URL`).
- Igual que el motor del stack principal (ver `docker-compose.yml` de la
  raiz, red `gvm_scan_egress`), `ospd-openvas` aca tiene una red separada
  CON salida real -- sin ella, ningun escaneo podria completarse, aunque
  gvmd este sano y respondiendo. Esa misma red conecta tambien al
  contenedor `openvas-agent` hacia afuera, para que pueda alcanzar
  `SCAN_SERVICE_URL`.
- Para actualizar los feeds mas adelante: `docker compose pull && docker
  compose up -d` trae las imagenes de feed mas nuevas (mismo mecanismo
  que el stack principal, ver `openvas/LEEME.md`).
- Para desplegar en varios sitios/LANs de clientes distintos, repeti
  estos 4 pasos en cada maquina -- cada una se registra como un agente
  aparte en la UI (nombrala segun el sitio, ej. `Agente OpenVAS -
  sucursal norte`).
- `remote-agent/agent.py` es el MISMO archivo que usan el Agente LAN y el
  Agente Docker del stack principal (se copia en build-time, ver
  `Dockerfile`) -- cualquier mejora futura al flujo GMP/openvas se
  escribe una sola vez y sirve para los 3.
