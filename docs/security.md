# TERO Security -- modelo de amenazas (STRIDE)

Este documento aplica STRIDE (Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege) a la arquitectura descrita
en `docs/architecture.md`. El objetivo es dejar explicitas las mitigaciones ya
implementadas y las que quedan como trabajo futuro, no presentar la plataforma
como libre de riesgo.

## Alcance

Cubre los 11 microservicios backend, el frontend, y los componentes de
infraestructura de `docker-compose.yml` / `infra/`. No cubre el codigo de terceros
(FastAPI, SQLAlchemy, Postgres, etc.) mas alla de su configuracion.

## Spoofing (suplantacion de identidad)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un atacante se autentica como otro usuario | JWT firmado (HS256) + bcrypt para passwords + MFA opcional (TOTP) en auth-service | Rotacion de `JWT_SECRET_KEY`; soportar MFA obligatorio por rol |
| Un servicio interno se hace pasar por otro | Los endpoints `/internal/*` (siem-service, integration-service) no tienen auth de usuario porque asumen red interna confiable (docker-compose/k8s namespace) | mTLS o un token de servicio compartido entre microservicios si se expone la red interna fuera del cluster |
| Un agente de escaneo remoto (`remote-agent/agent.py` o `remote-agent/agente-lan.ps1`, fuera de Docker, para redes LAN que el contenedor de scan-service no ve) falso se hace pasar por un agente registrado | Autenticacion propia por API key (header `X-Agent-Key`, nunca el JWT de un usuario); scan-service solo persiste el hash sha256 de la key (`_hash_agent_key` en `scan-service/app/services.py`), nunca el valor en texto plano; el agente solo puede pedir jobs y correr trivy/nuclei en modo deteccion, nunca ejecutar comandos arbitrarios | No hay rotacion de key sin borrar el agente (`DELETE /agents/{id}`) y crear uno nuevo; agregar rotacion sin perder el historial del agente |

## Tampering (alteracion de datos)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Modificar una alerta o caso para ocultar un incidente | Timeline de auditoria append-only en case-service; audit log con encadenamiento SHA-256 en auth-service | Extender el mismo encadenamiento hash a case-service y siem-service |
| Inyectar una condicion Sigma maliciosa que ejecute codigo | `app/sigma.py` evalua condiciones con un AST restringido (`_ALLOWED_CONDITION_NODES`), nunca `eval()` sobre texto arbitrario | Fuzzing periodico del evaluador de condiciones |
| Alterar un playbook YAML para ejecutar una accion no autorizada | Playbooks se sincronizan a Postgres al arrancar soar-service desde archivos versionados en el repo (revisados en PR) | Firmar los YAML de playbooks o restringir su origen a un directorio de solo-lectura en produccion |

## Repudiation (repudio)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un operador niega haber cerrado un caso o corrido un playbook | Timeline de casos y `PlaybookRunOut.triggered_by` registran actor y timestamp | Centralizar todos los logs estructurados (JSON, ver `backend/shared/logging.py`) en un SIEM externo con retencion garantizada |

## Information Disclosure (divulgacion de informacion)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Filtrar vulnerabilidades/CVEs de un cliente a otro | Multi-tenant con aislamiento por fila (`organization_id` en cada tabla de cada servicio, filtrado en cada query -- ver `backend/shared/tenancy.py`); el JWT lleva `org_id` y cada endpoint lo usa para scopear sus consultas | Auditoria periodica de que todo query nuevo filtre por `organization_id` (revisar en code review, no hay un enforcement automatico a nivel de DB tipo RLS todavia) |
| Exponer secretos (JWT secret, password de DB) en el repo | `.env` esta en `.gitignore`; `infra/k8s/base/secret.yaml` tambien; Terraform usa `TF_VAR_db_password` en vez de un default | Adoptar un secret manager real (Vault, AWS Secrets Manager) en vez de Secrets planos de k8s |
| Los endpoints internos (`/internal/rule-tags` de siem-service, `/internal/lookup-batch` de threatintel, `/internal/organizations` de auth) los llame alguien que no es un servicio | Exigen un JWT de servicio (`system:*`, `backend/shared/service_auth.py`); `rule-tags` toma la organizacion de los claims, no de un parametro | Restringir ademas por NetworkPolicy de k8s a los Pods que realmente los necesitan |

## Denial of Service

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un cliente HTTP abusivo agota conexiones a un servicio | Timeouts explicitos (10s) en todas las llamadas httpx entre servicios | Rate limiting a nivel de ingress/API gateway; readiness/liveness probes ya definidas en `infra/k8s/base` para que k8s reinicie Pods colgados |
| Un playbook mal configurado dispara un loop de acciones | Acciones de SOAR son idempotentes por diseño (bloquear la misma IP dos veces no es destructivo) y corren en dry-run por defecto | Circuit breaker / limite de ejecuciones por alerta en soar-service |

## Elevation of Privilege

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un usuario sin rol admin ejecuta una accion de contencion real | RBAC via claim `role` en el JWT, verificado con `require_role(...)` en cada endpoint sensible (crear conectores, generar reportes, etc.) | Auditoria periodica de que rol tiene acceso a que endpoint, a medida que se agregan mas roles |
| SOAR/integration-service ejecutan una accion real sin que un humano lo decida | Doble capa de dry-run independiente: `SOAR_DRY_RUN` e `INTEGRATION_DRY_RUN`, ambas en `"true"` por defecto en `docker-compose.yml`, `.env.example` e `infra/k8s/base/configmap.yaml`. Pasar a `"false"` es un cambio explicito de configuracion, nunca el valor de fabrica | Requerir ademas un conector configurado (ya implementado: sin conector habilitado, la accion queda `failed` aunque el dry-run este apagado) -- agregar una segunda aprobacion humana (four-eyes) antes de la primera ejecucion real en un cliente nuevo |

## Controles agregados en la auditoria (tanda 3)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un admin de organizacion da de alta el email de una persona ajena y la captura cuando entra con Google | `invite_email_error` (auth-service): con varias organizaciones, solo emails del mismo dominio que los usuarios de la org; correo gratuito (gmail, outlook...) reservado al platform_admin (o `ALLOW_FREEMAIL_INVITES=true` en instalaciones de una sola empresa) | Flujo de invitacion con confirmacion por email |
| Un dominio del atacante que resuelve a 127.0.0.1 / 169.254.169.254 usado como target de escaneo | `resolved_target_error` resuelve el DNS justo antes de lanzar el escaner y rechaza loopback/link-local/reservado (RFC1918 permitido a proposito) | DNS rebinding con TTL bajo (exigiria fijar la IP en el escaner) |
| Un analyst lee el filesystem del contenedor de scan-service via `gitleaks`/`semgrep` con un path local | `ScanJobCreate`/`ScanScheduleCreate` exigen una URL git http(s) para esos escaneres dentro del contenedor; los paths locales solo en un agente remoto | - |
| Un analyst lanza Falco/Zeek (eBPF/captura de todo el host) | Solo `admin` o `soc_manager` pueden lanzarlos en el contenedor | Limite de concurrencia/duracion por organizacion |
| Un link armado a mano `/sso/callback#access_token=...` deja a la victima en la cuenta del atacante | La SPA exige el valor `cs` (sessionStorage, un solo uso) que auth-service devuelve en el fragmento; sin coincidencia descarta la sesion | - |
| Nombre de playbook SOAR como oraculo de existencia entre organizaciones | Unico por organizacion (indice `uq_playbooks_org_name`) | - |
| Binario de gitleaks cambia entre builds | `ARG GITLEAKS_VERSION` fijo + verificacion contra `checksums.txt` de la release | Actualizar la version a mano de forma periodica |
| Instalacion nueva con los chequeos de entorno inertes (`ENVIRONMENT=development`) | El launcher crea `.env` con `ENVIRONMENT=production` (todos los secretos ya son aleatorios) | Instalaciones copiadas a mano de `.env.example`: cambiar a `production` tras poner secretos propios |
| Otros usuarios locales de Windows leen `.env` o modifican el script del agente LAN | `icacls` (usuario actual + SYSTEM + Administradores) sobre `.env` (launcher) y sobre la carpeta del agente (`agente-lan.ps1 -Install`) | Probar en un Windows real |
| Fuerza bruta de login cuando Redis cae | `check_rate_limit` usa un contador en memoria del proceso como respaldo (antes dejaba pasar todo) | Con varias replicas el limite efectivo es por proceso |
| Entradas gigantes en auth (password de MBs al hash, tokens enormes) | Topes de tamano en los schemas (password 128 al crear / 1024 al ingresar, TOTP 16, tokens 8192) | - |
| Claves de agente en el historial de git (`.env.bak`, commit 68e11a5) | Rotar con `tools\rotar-claves-agentes.ps1`; `.env*`/`*.bak` estan en `.gitignore` | Si el repo es publico, valorar limpiar el historial (git filter-repo) tras rotar |
| Pods de k8s como root / sin aislamiento de red | `runAsNonRoot` + `runAsUser: 1001` en cada Deployment; `networkpolicy.yaml.example` opcional | Aplicar y probar la politica de red en tu cluster |

## Resumen

Los controles mas fuertes de esta plataforma son estructurales, no solo de
codigo: **ninguna accion de contencion (bloquear IP, aislar host, enviar una
notificacion externa) puede llegar a un sistema real sin que dos flags de
entorno independientes se desactiven explicitamente y un conector real este
configurado.** Esto es intencional: el objetivo del producto es dar visibilidad
y automatizar el analisis, dejando la decision de actuar contra infraestructura
real siempre en manos de un humano.
