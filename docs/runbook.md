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

auth-service no tiene un seed de usuario por defecto. Registrar el primer
usuario con `POST /auth/register` en auth-service (puerto 8001) y asignarle
rol `admin` directamente en la base (o agregar ese paso a `make seed` cuando
exista un script de seed real).

## Habilitar MFA para un usuario

`POST /auth/mfa/enroll` devuelve un secreto TOTP; el usuario lo carga en su
app de MFA (Google Authenticator, Authy, etc.) y confirma con
`POST /auth/mfa/confirm`. A partir de ahi, `POST /auth/login` exige
`totp_code`.

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
