# SentinelOps -- runbook operativo

Procedimientos practicos para operar una instancia de SentinelOps. Para el
"por que" de cada decision de diseno, ver `architecture.md` y `security.md`.

## Arranque / apagado

```bash
cp .env.example .env        # completar POSTGRES_PASSWORD y JWT_SECRET_KEY reales
make up                     # docker compose up --build -d
make logs                   # seguir logs de todos los servicios
make down                   # apagar
```

En Windows, sin terminal: `SentinelOps - Iniciar.exe` / `SentinelOps -
Detener.exe` en la raiz del repo hacen lo mismo que `make up` / `make
down`, mas la verificacion de que Docker Desktop este instalado y
corriendo y la apertura automatica del dashboard (ver
`launcher/README.md`). Siguen necesitando Docker Desktop instalado -- no
reemplazan a Docker, solo automatizan los comandos.

Verificar que todo levanto: cada servicio expone `GET /health` en su puerto
(ver tabla de puertos en el `README.md` de la raiz). Un `curl` rapido:

```bash
for port in 8001 8002 8003 8004 8005 8006 8007 8008 8009 8010 8011; do
  echo "puerto $port: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:$port/health)"
done
```

## Primer usuario admin

auth-service asciende automaticamente a `admin` al primer usuario que
exista en toda la base (por password o por Google), la primera vez que el
servicio arranca despues de que ese usuario se creo -- no hace falta tocar
la base a mano. Los siguientes usuarios que se registren o entren con
Google quedan como `analyst`; un admin los puede ascender despues (todavia
no hay un endpoint dedicado para eso -- por ahora es un UPDATE directo en
la tabla `roles`/`users`, o pedimoslo si se necesita).

Por seguridad, `POST /auth/register` (el registro publico) ya no acepta
que el que se registra elija su propio rol -- si lo aceptara, cualquiera
podria auto-asignarse `admin`.

## Login/registro con Google (opcional)

auth-service acepta un ID token de Google en `POST /auth/google` (el
frontend lo obtiene con Google Identity Services y lo manda como
`credential`). Si el email no existe todavia, se crea la cuenta en el
momento con rol `analyst` y sin password (`auth_provider=google`); si ya
existe, simplemente inicia sesion. No pasa por MFA porque Google ya
verifico al usuario.

Para activarlo:

1. En https://console.cloud.google.com/apis/credentials crear una
   credencial de tipo "ID de cliente de OAuth" -> "Aplicacion web", con
   `http://localhost:5173` (y el dominio real en produccion) en
   "Origenes de JavaScript autorizados".
2. Copiar ese Client ID en **las dos** variables del `.env`:
   `GOOGLE_CLIENT_ID` (la valida el backend) y `VITE_GOOGLE_CLIENT_ID`
   (la usa el frontend para dibujar el boton). Es el mismo valor en
   ambas -- el Client ID de Google es publico, no es un secreto.
3. Reiniciar auth-service y frontend (`docker compose up -d --build`,
   o volver a correr el launcher en Windows).

Si se deja vacio, el boton de Google no aparece y el login con
email/password sigue funcionando igual que antes.

## Habilitar MFA para un usuario

`POST /auth/mfa/enroll` devuelve un secreto TOTP; el usuario lo carga en su
app de MFA (Google Authenticator, Authy, etc.) y confirma con
`POST /auth/mfa/confirm`. A partir de ahi, `POST /auth/login` exige
`totp_code`.

## Organizaciones (multi-tenancy) y SSO empresarial (OIDC)

SentinelOps es multi-tenant: cada organizacion (empresa cliente) es una
fila en `organizations` (auth-service) y todo el resto de las tablas de
la plataforma (activos, escaneos, vulnerabilidades, alertas SIEM,
playbooks/runs de SOAR, casos, ejercicios purple team, reportes, canales
de notificacion, conectores) tiene una columna `organization_id` que
aisla los datos de una organizacion de los de otra. Un usuario nunca ve
datos de una organizacion que no es la suya, ni siquiera adivinando un
UUID (los servicios devuelven 404, no 403, para no filtrar si un recurso
existe en otro tenant).

### platform_admin vs admin de organizacion

Son dos cosas distintas (ver `backend/services/auth-service/app/dependencies.py`):

- **admin** (rol normal): administra SU PROPIA organizacion -- usuarios,
  configuracion de SSO de su empresa. Un admin de la organizacion A nunca
  puede tocar nada de la organizacion B.
- **platform_admin** (flag separado, `User.is_platform_admin`): administra
  la plataforma ENTERA -- puede crear organizaciones nuevas y ver/editar
  el SSO de cualquiera. El primer usuario que se registra en toda la base
  se asciende automaticamente a `admin` + `platform_admin` (ver el
  lifespan de auth-service); todos los que le siguen entran como
  `analyst` en la organizacion "default" salvo que un platform_admin los
  de alta en una organizacion propia.

En el frontend, la pagina "Organizaciones" (`/organizations`, visible en
el menu solo para `admin`/`platform_admin`) cubre ambos casos: gestion de
organizaciones (solo platform_admin) y configuracion de SSO de una
organizacion (admin de esa organizacion, o platform_admin elegiendola de
la lista).

### Dar de alta una organizacion nueva

Solo un platform_admin puede hacerlo -- no hay auto-registro publico de
organizaciones a proposito (si lo hubiera, cualquiera podria crear una
"empresa" nueva sin ninguna verificacion). Un `POST /auth/organizations`
(o la pagina "Organizaciones" -> "Crear organizacion nueva") crea la
empresa y su primer usuario admin en un solo paso.

### Configurar SSO (OIDC) para una organizacion

Compatible con cualquier proveedor OIDC estandar: Azure AD / Microsoft
Entra ID, Okta, Google Workspace, Keycloak, Auth0, etc.

1. En el proveedor, registrar una aplicacion OIDC de tipo "Web" con el
   redirect URI `http://<host-de-auth-service>/auth/oidc/<slug-de-la-organizacion>/callback`
   (en local, `http://localhost:8001/auth/oidc/<slug>/callback`). El slug
   de la organizacion es el que devuelve `GET /auth/organizations`.
2. Pagina "Organizaciones" -> elegir la organizacion -> "Configurar SSO":
   completar el **issuer** (la URL base OIDC del proveedor, ej.
   `https://login.microsoftonline.com/<tenant>/v2.0`), el **client ID**,
   el **client secret** y el **rol por defecto** para los usuarios que
   entren por primera vez via SSO (`analyst` por defecto). Guardar con
   "Habilitado" marcado.
3. Los usuarios de esa organizacion ya pueden entrar sin password propia:
   en la pantalla de login, seccion "SSO empresarial", ingresan el slug
   de su organizacion y el navegador los manda al proveedor. Al volver,
   `/sso/callback` guarda la sesion y entra a la app.

**Notas de seguridad:**

- El `client_secret` nunca se vuelve a mostrar por API una vez guardado
  (`GET /auth/organizations/{id}/sso` no lo incluye) -- para cambiarlo,
  se sobreescribe con un `PUT` nuevo. **Limitacion conocida:** hoy se
  guarda en texto plano en la tabla `sso_configs` de Postgres (igual que
  las credenciales de conectores de integration-service); si el cliente
  lo requiere, cifrarlo a nivel de columna o moverlo a un secret manager
  externo es trabajo pendiente, no cubierto por este repo todavia.
- Un email que ya existe en otra organizacion no puede "entrar" a esta
  via SSO (403) -- evita que un SSO mal configurado en la empresa B
  autentique como si fuera un usuario de la empresa A.
- El `state` que viaja ida y vuelta con el proveedor es un JWT propio de
  vida corta (5 minutos) firmado con `JWT_SECRET_KEY` -- hace de
  proteccion CSRF sin necesitar sesiones de servidor.

### Playbooks globales vs por organizacion (soar-service)

Los playbooks que vienen con la plataforma (sincronizados desde YAML al
arrancar soar-service, ver `app/playbook_loader.py`) tienen
`organization_id = NULL` a proposito -- significa "global, visible para
todas las organizaciones", no "todavia sin migrar". Un playbook nuevo
creado por una organizacion via `POST /playbooks` si tiene su propio
`organization_id` y solo esa organizacion lo ve. Editar un playbook
global (`PATCH /playbooks/{id}` sobre uno con `organization_id = NULL`)
requiere `platform_admin` -- si no, cualquier admin de cualquier
organizacion podria modificar sin querer un playbook que corre para
todos los clientes.

### Logs (siem-service / OpenSearch) por organizacion

Cada evento normalizado que llega a `POST /logs/ingest` guarda
`organization_id` como campo de nivel superior en el documento de
OpenSearch (no anidado). `GET /logs/search` siempre agrega
`{"term": {"organization_id": ...}}` a la busqueda -- un analista de una
organizacion nunca ve logs de otra, aunque comparta el mismo indice de
OpenSearch.

## Pasar de dry-run a acciones reales (SOAR / integraciones / notificaciones)

**No hacer esto sin que el cliente lo pida explicitamente y entienda las
consecuencias.** Por defecto, SentinelOps nunca toca infraestructura real:

1. **Notificaciones reales** (email/Slack): configurar un canal real en
   notification-service (`POST /channels` con `webhook_url` o los datos SMTP
   via variables `SMTP_*`), y poner `NOTIFICATION_DRY_RUN=false` en el
   entorno de ese servicio. Probar primero con `POST /notify` manual antes
   de dejar que las alertas lo disparen solas.
2. **Contencion real** (bloquear IP / aislar host): configurar un conector
   en integration-service (`POST /connectors`, con `base_url` de un webhook
   que ya sepa hablarle al firewall/EDR real del cliente) y poner
   `INTEGRATION_DRY_RUN=false`. Sin un conector habilitado del tipo
   correcto (`firewall` o `edr`), la accion sigue fallando de forma segura
   aunque el dry-run este apagado.
3. Solo despues de 1 y 2, poner `SOAR_DRY_RUN=false` en soar-service para
   que sus playbooks dejen de simular y empiecen a delegar en
   integration-service de verdad.

Revertir cualquiera de estos tres flags a `true` (o `false` -> quitar el
conector) vuelve inmediatamente al modo seguro.

## Incidentes comunes

**Un servicio no arranca / `/health` no responde**: revisar
`docker compose logs <servicio>`. La causa mas comun es que Postgres/Redis
todavia no terminaron su healthcheck -- `depends_on: condition:
service_healthy` deberia evitar esto, pero un arranque en frio de OpenSearch
puede tardar mas de lo que espera siem-service.

**siem-service no genera alertas para un log que deberia matchear una
regla**: revisar que la regla este `is_enabled: true` (`GET /rules`) y que
la condicion Sigma solo use nombres de selection definidos (el evaluador en
`app/sigma.py` devuelve `False` de forma segura ante cualquier nombre no
reconocido, en vez de fallar con una excepcion).

**Un caso importado desde soar-service aparece duplicado**:
`import_pending_cases_from_soar` en case-service dedupe por
`alert_id + source` -- si aun asi se duplica, revisar que soar-service no
este generando `PendingCase` con un `alert_id` distinto para la misma
alerta real.

**purple-service reporta 0% de cobertura para todo**: siem-service no esta
respondiendo en `SIEM_SERVICE_URL` (revisar esa variable de entorno) o
ninguna regla tiene tags con la convencion `attack.tXXXX` -- ver
`_TAG_TECHNIQUE_RE` en `purple-service/app/services.py`.

**Un escaneo de un rango LAN (`192.168.x.x`, `10.x.x.x`, etc.) no encuentra
nada, o tarda y termina en timeout**: el escaneo corre DENTRO del
contenedor de scan-service, no en la red real de la maquina que corre
Docker. Docker Desktop (Windows/Mac) pone al contenedor detras de NAT en
una red propia, asi que no llega a los dispositivos de la LAN/oficina del
usuario salvo que se le de acceso explicito a esa red (o se despliegue en
Linux con `network_mode: host`, que Docker Desktop no soporta igual). Para
escanear la red real de una empresa en produccion, este servicio tiene que
correr en una maquina (o un agente) que este efectivamente conectado a esa
red -- no alcanza con apuntar el target a un rango LAN desde una laptop con
Docker Desktop. El driver de nmap (`app/scanners/nmap.py`) usa `-T4` y
`--host-timeout 30s` para que un rango inalcanzable falle rapido (unos
minutos) en vez de comerse el timeout entero por cada host que no
responde.

**"SCANNER_UNAVAILABLE" en un job**: el binario de ese scanner no esta en
la imagen de scan-service. nmap, trivy y nuclei se instalan en el
Dockerfile (trivy y nuclei via su release oficial, no hay paquete apt);
openvas/gvm-cli NO se instala a proposito -- es un producto completo
(gvmd + su propia base de datos + feed de NVTs), no un CLI suelto, asi que
queda marcado como no disponible en vez de intentar empaquetarlo. Notar
tambien que trivy espera un nombre de imagen o una ruta de filesystem como
target (no una IP), y nuclei espera un host/URL alcanzable por HTTP -- un
target de IP/CIDR pensado para nmap no necesariamente tiene sentido para
esos otros dos scanners.

## Reportes programados por email

report-service puede generar un reporte solo (segun una regla de
frecuencia diaria/semanal) y mandarlo por email como PDF adjunto, sin
intervencion manual -- se crea desde la pagina "Reportes" del frontend
("Reportes programados"). Corre con un scheduler en proceso (APScheduler,
mismo patron que las reglas de escaneo programado de scan-service), asi
que no hace falta infraestructura de colas extra; si el contenedor se
reinicia, las reglas habilitadas se vuelven a cargar solas al arrancar.

Requisitos para que el envio real funcione (no solo quede en dry-run):

- Crear al menos un canal de notificaciones tipo `email` en
  notification-service (`POST /channels`, `channel_type: "email"`, con
  `config.smtp_to` = destinatario) -- se elige al crear la regla.
- Configurar `SMTP_HOST` (y `SMTP_PORT`/`SMTP_USER`/`SMTP_PASSWORD`/
  `SMTP_FROM` segun el proveedor) en el `.env` de notification-service.
  Sin `SMTP_HOST`, el envio queda registrado como `failed` con el motivo
  ("SMTP_HOST no configurado").
- Poner `NOTIFICATION_DRY_RUN=false` en el `.env` -- por defecto esta en
  `true` (igual que SOAR_DRY_RUN), asi que las notificaciones (incluidos
  los reportes programados) se registran como `simulated` sin mandar
  nada real hasta que se cambie explicitamente.

report-service llama a los demas servicios (vuln/siem/case/purple) con un
token de servicio propio que el mismo minta (subject
`system:report-scheduler`, rol `admin`, mismo `JWT_SECRET_KEY` compartido
via el `.env` comun) -- no hace falta ningun usuario interactivo detras de
una corrida programada. Si algun paso falla (un servicio fuente no
responde, el envio de email falla, etc.), se registra en el campo
"Ultima corrida" de la regla y NO tumba el scheduler -- la proxima corrida
programada se intenta igual.

Tambien se puede pedir el PDF de cualquier reporte ya generado a mano
desde `GET /reports/{id}/export?format=pdf` (o el boton "PDF" en el
historial de la pagina Reportes), sin necesidad de una regla programada.

Como con las reglas de escaneo programado (ver scan-service), tanto el
scheduler de report-service como cada regla usan un timezone explicito
(`SCHEDULER_TIMEZONE`, default `UTC`) -- APScheduler intenta autodetectar
la zona horaria del sistema si no se le pasa una, y eso puede fallar en la
imagen Debian "slim" del contenedor.

## Integracion con Jira y Slack desde SOAR

integration-service ahora soporta un tercer tipo de conector,
`ticketing` (ej. Jira), ademas de `firewall`/`edr`. Un conector de Jira
se crea desde "Integraciones" (o `POST /connectors`, rol admin) con:

```json
{
  "base_url": "https://tuempresa.atlassian.net",
  "email": "soc@tuempresa.com",
  "api_token": "...",
  "project_key": "SEC",
  "issue_type": "Task",
  "priority_map": { "critical": "Highest", "high": "High" }
}
```

`api_token` es un token de API de Atlassian (no la contraseña de la
cuenta). `priority_map` es opcional -- sin el, el ticket se crea sin
campo de prioridad (los nombres de prioridad son especificos de cada
instancia de Jira y ponerlos mal tira un 400).

Slack (y email) ya se resuelven con notification-service: un canal
`slack_webhook` (con `config.webhook_url` = la Incoming Webhook URL de
Slack) o `email` alcanza; no hace falta nada nuevo en integration-service
para eso.

Para que un playbook de SOAR dispare esto automaticamente hay dos
acciones nuevas disponibles en sus `steps` (ver "SOAR" en el frontend
para crear un playbook, o los YAML de ejemplo en
`backend/services/soar-service/playbooks/`):

- `create_ticket`: abre un ticket via el conector `ticketing` habilitado
  (`abrir_ticket_jira.yaml`, min_severity high).
- `notify`: notifica a todos los canales habilitados de
  notification-service (`notificar_equipo.yaml`, min_severity medium).

Ambas respetan la misma cadena de dry-run por defecto que el resto de
SOAR: quedan simuladas mientras `SOAR_DRY_RUN` (soar-service),
`INTEGRATION_DRY_RUN` (integration-service) o `NOTIFICATION_DRY_RUN`
(notification-service) sigan en `true` -- hay que desactivar
explicitamente el nivel correspondiente para que la accion real (crear
el ticket en Jira / mandar el mensaje a Slack) se ejecute.

## Agente de escaneo remoto

**Para que sirve.** Docker Desktop (Windows/Mac) aisla a los contenedores
detras de NAT: scan-service, corriendo adentro de Docker, no ve la LAN
real de la oficina/cliente aunque Docker este instalado en una PC de esa
misma red. Un escaneo nmap contra `192.168.1.0/24` lanzado desde la UI
no encuentra nada en ese caso -- no es un bug, es una limitacion de red
del propio Docker Desktop.

**Como se resuelve.** `remote-agent/agent.py` (en la raiz del repo) es un
script Python que corre FUERA de Docker -- en la misma PC donde esta
SentinelOps, o en cualquier otra maquina de la LAN con visibilidad real
a la red que se quiere escanear. El agente hace **polling** hacia
scan-service (siempre el agente inicia la conexion, nunca al reves), asi
que no hace falta abrir ningun puerto de entrada en la red del cliente:
alcanza con que el agente pueda llegar, de salida, al puerto ya publicado
de scan-service (`8003`). No hay ningun relay ni endpoint publico en
internet -- el uso tipico es on-prem, dentro de la misma red del cliente.

**Autenticacion.** El agente usa una api key propia (nunca el JWT de un
usuario humano), enviada en el header `X-Agent-Key`. scan-service solo
guarda el hash (sha256) de esa key -- se muestra en texto plano una unica
vez, al registrar el agente desde la UI (pagina Escaneos -> "Agentes de
escaneo remoto"). Sha256 alcanza aca (y no un hash lento tipo bcrypt)
porque la propia key ya es un secreto de alta entropia generado por el
servidor, no una contraseña elegida por una persona -- y el poll ocurre
cada pocos segundos, asi que un hash costoso ahi si seria un problema de
performance real.

**Alcance.** El agente solo sabe correr nmap en modo deteccion
(descubrimiento de puertos/servicios + scripts `default,safe`) -- el
mismo comando exacto y las mismas restricciones que usa scan-service
adentro del contenedor. Nunca ejecuta `--script vuln` ni scripts de las
categorias `exploit`/`intrusive`.

**Como se usa.**
1. Pagina Escaneos -> "Agentes de escaneo remoto" -> "Registrar agente"
   (requiere rol `admin`). Copiar la api key que se muestra (una sola
   vez).
2. En la maquina donde va a correr el agente: configurar
   `AGENT_API_KEY` (la key del paso 1) y `SCAN_SERVICE_URL` (si el agente
   corre en otra maquina de la LAN, usar la IP de la PC de SentinelOps
   en vez de `localhost`) como variables de entorno, y correr
   `python remote-agent/agent.py` (requiere Python 3.9+ y nmap instalado
   -- ver `remote-agent/README.md` para el detalle completo, incluyendo
   Windows).
3. Pagina Escaneos -> "Escaneos remotos" -> elegir el agente y el target,
   lanzar el escaneo. El agente lo recoge en su siguiente poll y manda el
   resultado solo; los hallazgos se reenvian automaticamente a
   vuln-service para priorizacion, igual que un escaneo normal.

## Backups

- **Postgres**: es la unica fuente de verdad para casi todos los servicios
  (activos, vulnerabilidades, casos, ejercicios purple team, reportes
  generados, canales de notificacion, conectores). En AWS via
  `infra/terraform`, RDS ya tiene `backup_retention_period = 7` dias; en
  `docker-compose.yml` local no hay backup automatico -- usar
  `pg_dump` periodicamente si se corre en produccion sin RDS.
- **OpenSearch**: contiene logs normalizados. Definir una politica de
  retencion/snapshot separada segun el volumen real de logs del cliente;
  no esta cubierta todavia por este repo.

## Escalar

En Kubernetes (`infra/k8s/base`), cada Deployment de microservicio ya pide
2 replicas -- escalar con `kubectl -n sentinelops scale deployment
<servicio> --replicas=N`. Los servicios son stateless (el estado vive en
Postgres/Redis/OpenSearch), asi que escalar horizontalmente es seguro sin
cambios de codigo.
