# Estado del proyecto SentinelOps (seginfo-toolkit)

Alcance: plataforma de ciberseguridad DEFENSIVA (SIEM/SOAR, gestion de vulnerabilidades
en modo escaneo, gestion de casos, cumplimiento, reportes, dashboard). No incluye
motores de ejecucion ofensiva ni integracion C2 (ver docs/architecture.md, seccion
"Fuera de alcance").

## Fases
- [x] Fase 1: Arquitectura + docker-compose + estructura + auth-service + frontend base
- [x] Fase 2: asset-service + scan-service (orquestacion de escaneres defensivos) + vuln-service
- [x] Fase 3: siem-service + soar-service
- [ ] Fase 4: case-service + purple-service (metricas/gap-analysis, sin motor ofensivo)
- [ ] Fase 5: report-service + notification-service + integration-service
- [ ] Fase 6: K8s + Terraform + CI/CD completo + documentacion final

## Ultima corrida
- Fecha: 2026-09-22
- Fase completada: 3
- Proxima fase: 4
- Notas: siem-service (ingesta de logs -> normalizacion ECS-lite -> OpenSearch,
  motor de reglas Sigma con condicion evaluada de forma segura via AST -- nunca
  eval() sobre texto arbitrario -- y generacion de alertas) y soar-service
  (playbooks YAML sincronizados a Postgres, motor de ejecucion secuencial de pasos
  con matching por severidad minima, acciones block_ip/isolate_host/create_case
  TODAS en modo DRY-RUN por defecto -- SOAR_DRY_RUN=true -- ya que integration-service,
  Fase 5, todavia no provee conectores reales de firewall/EDR; create_case guarda
  PendingCase en la propia base cuando case-service, Fase 4, todavia no existe).
  siem-service notifica a soar-service via POST /trigger ante cada alerta nueva
  (best-effort, no bloqueante). Se agrego el servicio opensearch a docker-compose.yml
  y se conectaron siem-service/soar-service siguiendo el mismo patron de Dockerfile
  que el resto. Validado con py_compile (todos los .py del proyecto, sin errores) y
  docker-compose.yml como YAML valido (docker no disponible en esta maquina de
  automatizacion para correr `docker compose config` con builds reales).
- Pendiente: el token de GitHub usado por esta automatizacion no tiene permiso
  'Workflows', asi que el workflow de CI (.github/workflows/ci.yml) no se pudo subir.
  Si el usuario agrega ese permiso al token, una proxima corrida puede subirlo
  (esto se resuelve a fondo en la Fase 6, que cubre CI/CD). El frontend todavia no
  tiene vistas para activos/escaneos/vulnerabilidades/SIEM/SOAR -- esto esta
  contemplado para la Fase 6 (expansion del frontend).
