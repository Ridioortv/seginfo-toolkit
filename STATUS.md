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
- [ ] Fase 5: report-service + notification-service + integration-service
- [ ] Fase 6: K8s + Terraform + CI/CD completo + documentacion final

## Ultima corrida
- Fecha: 2026-09-22
- Fase completada: 4
- Proxima fase: 5
- Notas: case-service (gestion de incidentes estilo ITSM/kanban: prioridad con
  SLA calculado automaticamente por tabla SLA_HOURS_BY_PRIORITY (critical=4h,
  high=8h, medium=24h, low=72h), timeline de auditoria por caso, cierre con
  resolved_at automatico, e importacion best-effort de PendingCase generados
  por soar-service via POST /import/soar-pending con dedupe por alert_id+source)
  y purple-service (gap analysis de cobertura de deteccion MITRE ATT&CK -- SOLO
  analiza datos, nunca ejecuta tecnicas: un catalogo curado de 12 tecnicas de
  referencia en app/attack_data.py se cruza contra las reglas Sigma habilitadas
  de siem-service, consultadas via un nuevo endpoint interno sin auth de usuario
  GET /internal/rule-tags pensado solo para llamadas servicio-a-servicio dentro
  de la red de docker-compose; el matching busca tags con convencion
  'attack.tXXXX' y calcula cobertura global -- GET /coverage/overall, metrica de
  dashboard -- y por ejercicio declarado -- POST /exercises/{id}/coverage,
  persistiendo el resultado en el propio ejercicio). Se conecto CASE_SERVICE_URL
  en soar-service ahora que case-service existe (antes estaba vacio). Se
  agregaron case-service (puerto 8007) y purple-service (puerto 8008) a
  docker-compose.yml siguiendo el mismo patron de Dockerfile/build-context que
  el resto, y se actualizo el depends_on de frontend. Validado con py_compile
  (todos los .py nuevos/modificados, sin errores) y docker-compose.yml parseado
  como YAML valido con pyyaml (12 servicios, docker no disponible en esta
  maquina de automatizacion para correr `docker compose config` con builds
  reales).
- Pendiente: el token de GitHub usado por esta automatizacion no tiene permiso
  'Workflows', asi que el workflow de CI (.github/workflows/ci.yml) no se pudo
  subir. Si el usuario agrega ese permiso al token, una proxima corrida puede
  subirlo (esto se resuelve a fondo en la Fase 6, que cubre CI/CD). El frontend
  todavia no tiene vistas para activos/escaneos/vulnerabilidades/SIEM/SOAR/
  Casos/PurpleTeam -- esto esta contemplado para la Fase 6 (expansion del
  frontend). Fase 5 (report-service, notification-service, integration-service)
  queda pendiente para la proxima corrida.
