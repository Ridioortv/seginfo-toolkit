# Estado del proyecto SentinelOps (seginfo-toolkit)

Alcance: plataforma de ciberseguridad DEFENSIVA (SIEM/SOAR, gestion de vulnerabilidades
en modo escaneo, gestion de casos, cumplimiento, reportes, dashboard). No incluye
motores de ejecucion ofensiva ni integracion C2 (ver docs/architecture.md, seccion
"Fuera de alcance").

## Fases
- [x] Fase 1: Arquitectura + docker-compose + estructura + auth-service + frontend base
- [x] Fase 2: asset-service + scan-service (orquestacion de escaneres defensivos) + vuln-service
- [x] Fase 3: siem-service + soar-service
- [x] Fase 4: case-service + purple-service (metricas/gap-analysis, sin motor ofensivo)
- [x] Fase 5: report-service + notification-service + integration-service
- [x] Fase 6: K8s + Terraform + CI/CD + documentacion final + expansion de frontend

## Ultima corrida
- Fecha: 2026-09-22
- Fase completada: 6
- Proxima fase: ninguna -- las 6 fases planificadas estan completas. Las
  proximas corridas (ver PASO 3 del prompt de la tarea programada) se
  dedican a calidad: agregar tests reales, revisar cobertura, mejorar
  documentacion floja.
- Notas Fase 6: se completo el frontend con vistas para los 11
  microservicios backend -- Dashboard (resumen ejecutivo agregando
  vuln-stats/alertas/casos/cobertura ATT&CK), Assets, Scans,
  Vulnerabilities, Siem (alertas + reglas), Soar (playbooks + ejecuciones),
  Cases (con indicador visual de SLA vencido), PurpleTeam (catalogo de
  tecnicas + cobertura + ejercicios), Reports (generar + descargar CSV con
  fetch autenticado, nunca un link directo sin token), Notifications
  (canales + prueba de envio + historial) e Integrations (conectores +
  historial de acciones) -- mas un store de auth (zustand, persistido en
  localStorage) y react-router con ProtectedRoute. Se alinearon las
  variables VITE_*_API_BASE_URL del frontend con la convencion ya
  establecida en .env.example desde la Fase 1 (antes usaban un esquema de
  nombres distinto e inconsistente). Se agrego infra/k8s/base (Kustomize):
  namespace, ConfigMap/Secret-template, Postgres/Redis/OpenSearch, un
  Deployment+Service por microservicio + frontend, e Ingress de ejemplo;
  todos los YAML se validaron sintacticamente. Se agrego infra/terraform:
  esqueleto de AWS (VPC con subredes publicas/privadas + NAT, EKS con node
  group administrado, RDS Postgres, ElastiCache Redis, OpenSearch
  administrado, un repo ECR por servicio); validado como HCL sintacticamente
  correcto con python-hcl2 (terraform CLI no disponible en esta maquina de
  automatizacion). Se agrego .github/workflows/ci.yml: py_compile del
  backend, build+typecheck del frontend, validacion de docker-compose.yml,
  y build (sin push todavia) de cada imagen Docker en un job matrix -- el
  push a un registry real queda pendiente de que el token de git tenga
  permiso 'Workflows' (ver Pendiente) y de decidir el registry final.
  Documentacion final: README.md actualizado con la lista completa de
  servicios/puertos y los nuevos directorios de infra; docs/security.md
  (modelo de amenazas STRIDE, con mitigaciones actuales vs. pendientes por
  categoria); docs/runbook.md (arranque, primer admin, como habilitar MFA,
  como pasar de dry-run a acciones reales en 3 pasos, incidentes comunes,
  backups, como escalar en k8s). Validacion final: py_compile sobre todo
  backend/ sin errores; docker-compose.yml, ci.yml y los 19 YAML de
  infra/k8s/base parseados como YAML valido; los 9 archivos de
  infra/terraform parseados como HCL valido; los 20 archivos .ts/.tsx del
  frontend transpilados sin errores de sintaxis con esbuild (tsc completo
  no se pudo correr: el node_modules local quedo en un estado corrupto por
  una instalacion de npm interrumpida en esta misma corrida, y no se pudo
  limpiar por una restriccion de borrado de archivos de esta maquina de
  automatizacion -- no afecta al repo, node_modules esta en .gitignore).

- Pendiente: el token de GitHub usado por esta automatizacion no tiene
  permiso 'Workflows' -- el push de este commit fue rechazado por GitHub
  ("refusing to allow a Personal Access Token to create or update
  workflow ... without workflow scope") hasta sacar
  .github/workflows/ci.yml del commit. El archivo quedo escrito en disco
  (en la carpeta conectada, sin commitear) con el pipeline completo
  (py_compile del backend, build+typecheck del frontend, validacion de
  docker-compose.yml, build de cada imagen Docker); para subirlo, Manu
  puede agregarle el permiso 'Workflows: Read and write' al token (en
  GitHub, Settings del fine-grained PAT) y correr `git add
  .github/workflows/ci.yml && git commit -m "Agrega CI" && git push`
  desde su PC, o pedirle a una proxima corrida automatica que lo haga una
  vez tenga ese permiso. El CI
  todavia no hace push de las imagenes Docker a ningun registry (falta
  decidir cual -- GHCR es la opcion mas simple porque no requiere
  credenciales de AWS -- y agregar el login+push al job `docker-build` de
  ci.yml). Ningun conector de firewall/EDR real esta configurado todavia en
  integration-service (ni deberia estarlo sin que el usuario/operador lo
  decida explicitamente) -- la plataforma queda en modo 100%
  dry-run/simulado en las tres capas (SOAR_DRY_RUN, INTEGRATION_DRY_RUN,
  NOTIFICATION_DRY_RUN) por defecto, en docker-compose, .env.example E
  infra/k8s/base/configmap.yaml. infra/terraform no fue aplicado contra
  ninguna cuenta de AWS real (es intencionalmente un esqueleto de
  referencia, ver infra/terraform/README.md para lo que falta revisar
  antes de un uso real: costos, security groups, backend remoto de
  estado). No existen tests automatizados (pytest/vitest) todavia en
  ningun servicio -- las 6 fases planificadas del proyecto estan
  completas; las proximas corridas de la tarea programada se dedican a
  agregar cobertura de tests reales y pulir documentacion floja, siguiendo
  el PASO 3 del prompt de la tarea ("si las 6 fases ya estan completas...
  dedica la corrida a mejorar calidad").
