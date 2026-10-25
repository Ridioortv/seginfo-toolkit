# TERO Security (seginfo-toolkit)

Plataforma de ciberseguridad defensiva: gestion de activos, escaneo de vulnerabilidades,
SIEM/SOAR, gestion de casos, purple team (metricas de deteccion), reportes de
cumplimiento, notificaciones e integraciones de contencion. Pensada para vender a
empresas como producto propio.

## Alcance

Este proyecto cubre exclusivamente el lado DEFENSIVO de una plataforma de seguridad:

- Inventario de activos (CMDB)
- Orquestacion de escaneres de vulnerabilidades (Trivy, Nuclei) en modo
  deteccion — nunca explotacion
- Priorizacion con CVSS / EPSS / CISA KEV
- SIEM: ingesta, normalizacion, correlacion de reglas Sigma, alertas
- SOAR: playbooks de respuesta automatizada (bloquear IP, aislar host, abrir caso),
  en modo DRY-RUN por defecto
- Gestion de casos e incidentes (estilo ITSM, con SLA por prioridad)
- Purple team: mapeo de cobertura de deteccion contra MITRE ATT&CK y gap analysis
  (analisis y metricas sobre datos declarados — sin motor de ejecucion de tecnicas
  ofensivas ni integracion C2)
- Reportes ejecutivos/de cumplimiento generados agregando datos ya existentes de los
  demas servicios
- Notificaciones (email/Slack/webhook) e integraciones de contencion (firewall/EDR
  genericos), ambas en modo DRY-RUN por defecto

Deliberadamente NO incluye: frameworks C2, orquestacion de exploits, o cualquier
componente que ejecute ataques reales contra objetivos. Ver
[`docs/architecture.md`](./docs/architecture.md) para el detalle de arquitectura y el
motivo de este recorte, y [`docs/security.md`](./docs/security.md) para el modelo de
amenazas (STRIDE).

## Estado de avance

Ver [`STATUS.md`](./STATUS.md) — el proyecto se construye en fases, una por dia,
mediante una tarea programada.

## Arranque local

```bash
cp .env.example .env
make up
```

Esto levanta Postgres, Redis, OpenSearch y los 11 microservicios backend + el
frontend con `docker-compose.yml`. Ver la tabla de puertos abajo.

### En Windows, sin usar la linea de comandos

Doble click en `TERO Security - Iniciar.exe` (raiz del repo): revisa que
Docker Desktop este instalado y corriendo, levanta todo con Docker Compose
y abre el dashboard solo. `TERO Security - Detener.exe` para todo sin borrar
los datos. Siguen necesitando Docker Desktop instalado -- ver
[`launcher/README.md`](./launcher/README.md) para el detalle y como
recompilarlos.

## Servicios y puertos (docker-compose)

| Servicio               | Puerto | Rol                                                    |
|------------------------|--------|---------------------------------------------------------|
| auth-service           | 8001   | Identidad, JWT, MFA (TOTP), RBAC                        |
| asset-service          | 8002   | Inventario de activos (CMDB)                            |
| scan-service           | 8003   | Orquestacion de escaneres (deteccion, no explotacion)   |
| vuln-service           | 8004   | CVSS/EPSS/CISA-KEV, priorizacion, triage                |
| siem-service           | 8005   | Ingesta de logs, reglas Sigma, alertas                  |
| soar-service           | 8006   | Playbooks de respuesta (dry-run por defecto)            |
| case-service           | 8007   | Incidentes, SLA, timeline                               |
| purple-service         | 8008   | Gap analysis de cobertura MITRE ATT&CK                  |
| report-service         | 8009   | Reportes ejecutivos/de cumplimiento                     |
| notification-service   | 8010   | Canales de aviso (dry-run por defecto)                  |
| integration-service    | 8011   | Conectores de contencion (dry-run por defecto)          |
| frontend               | 5173   | SPA React + TypeScript, tema oscuro tipo SOC            |

## Estructura

```
backend/
  shared/            # utilidades comunes (db, seguridad, logging)
  services/
    auth-service/        # identidad, JWT, MFA (TOTP), RBAC
    asset-service/        # inventario de activos
    scan-service/          # orquestacion de escaneres
    vuln-service/          # priorizacion de vulnerabilidades
    siem-service/          # ingesta, reglas Sigma, alertas
    soar-service/          # playbooks de respuesta (dry-run)
    case-service/          # incidentes/SLA/timeline
    purple-service/        # gap analysis MITRE ATT&CK
    report-service/        # reportes ejecutivos/cumplimiento
    notification-service/  # canales de aviso (dry-run)
    integration-service/   # conectores de contencion (dry-run)
frontend/            # SPA React + TypeScript, dashboard oscuro tipo SOC
infra/
  k8s/base/          # manifiestos de Kubernetes (Kustomize)
  terraform/         # esqueleto de infraestructura AWS (VPC/EKS/RDS/...)
docs/                # arquitectura, modelo de amenazas y runbook
.github/workflows/   # CI (py_compile, build de frontend, build de imagenes)
```

## Despliegue

- **Local / demo**: `docker-compose.yml` (ver arriba).
- **Kubernetes**: manifiestos en [`infra/k8s/base`](./infra/k8s/base) (Kustomize) —
  ver el README de esa carpeta antes de aplicar.
- **AWS (infraestructura)**: esqueleto de Terraform en
  [`infra/terraform`](./infra/terraform) — VPC, EKS, RDS, ElastiCache, OpenSearch, ECR.
- **CI**: [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) — chequeo de
  sintaxis del backend, build+typecheck del frontend, validacion de
  `docker-compose.yml` y build (sin push todavia) de cada imagen Docker.

## Gobernanza de IA en el codigo

Menu **Gobernanza de IA** (`/ai-governance`, servicio `coderepo-service`). Al escanear un repositorio conectado
en **Codigo y Repositorios**, TERO lee su historial de git y arma, por commit: quien lo escribio, si fue una
persona, una IA o ambas (por las marcas del commit o por declaracion manual), cuantas lineas toco y que
hallazgos tiene (secretos y patrones inseguros). Sobre eso:

- **Compuerta de seguridad** antes de integrar cambios (tambien consultable desde GitHub Actions).
- **Politicas por equipo o zona** del codigo (IA permitida / con revision / prohibida, aprobaciones, umbral de
  severidad), en modo *Observar* (solo mide) o *Exigir* (bloquea).
- **Registro auditable**: encadenado y firmado, exportable (JSON verificable / CSV) y con ancla externa.
- **Tablero para direccion**: porcentaje de codigo con IA, cobertura de revision, hallazgos cada 1000 lineas.

Guia completa, variables y limites en [`docs/gobernanza-ia.md`](./docs/gobernanza-ia.md).

## Confianza y evidencia

Menu **Confianza y evidencia** (`/trust`). Lo que TERO puede *demostrar* a un auditor, un cliente o un juez sin
pedirle que confie en nosotros:

- **Cadena de custodia digital**: alertas, respuestas, cambios de estado, escaneos y cierres quedan en una
  cadena firmada (Ed25519). Se exporta un paquete de evidencia por caso (`.zip`) con un verificador
  independiente que corre sin acceso a TERO.
- **Prueba de soberania**: auditor de salidas a internet (que servicio habla con que destino, para que y que
  datos viajan), modo aislado (`docker-compose.aislado.yml`), prueba de red y atestado firmado.
- **Cierre verificado**: al marcar una vulnerabilidad como remediada, TERO repite el escaneo que la encontro y
  solo la da por cerrada si ya no aparece (si sigue, la reabre sola). Mide el tiempo de cierre real y entrega
  una prueba firmada.

Guia completa, configuracion y limites en [`docs/confianza-y-evidencia.md`](./docs/confianza-y-evidencia.md).

## Olvide mi contrasena

En la pantalla de entrada: **¿Olvidaste tu contrasena?** -> email -> link de un solo uso (30 min). Requiere
`SMTP_HOST` en `.env`; sin mail, un administrador genera el link en **Usuarios y roles -> Restablecer
contrasena**. Ya adentro: **Seguridad de la cuenta -> Cambiar contrasena**. Detalle y topes en
`backend/services/auth-service/app/password_reset.py`.

## Operacion

Ver [`docs/runbook.md`](./docs/runbook.md) para procedimientos operativos
(arranque, incidentes comunes, como habilitar acciones reales de SOAR/integraciones
saliendo del modo dry-run, backups).
