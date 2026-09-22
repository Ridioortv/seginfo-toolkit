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
- [ ] Fase 6: K8s + Terraform + CI/CD completo + documentacion final

## Ultima corrida
- Fecha: 2026-09-22
- Fase completada: 5
- Proxima fase: 6
- Notas Fase 5: report-service (reportes ejecutivos/de cumplimiento generados
  100% agregando datos ya existentes en otros servicios -- vuln-service,
  siem-service, case-service, purple-service -- reenviando el token del
  usuario que pide el reporte, nunca con credenciales de servicio elevadas;
  si una fuente no responde esa seccion queda vacia con su error registrado,
  nunca se inventan datos; exportable como JSON o CSV via
  GET /reports/{id}/export). notification-service (canales configurables
  email/Slack-webhook/webhook-generico; por defecto en modo DRY-RUN
  -- NOTIFICATION_DRY_RUN=true, mismo patron que SOAR_DRY_RUN -- que registra
  la notificacion que se enviaria sin llamar de verdad a la URL/SMTP que
  configure el operador). integration-service (conectores GENERICOS tipo
  webhook REST de contencion -- firewall/EDR -- sin SDKs propietarios de
  ningun vendor; por defecto en modo DRY-RUN -- INTEGRATION_DRY_RUN=true --
  que tampoco llama a ningun sistema real; expone endpoints internos sin
  auth de usuario /internal/actions/block-ip y /internal/actions/isolate-host
  pensados para llamadas servicio-a-servicio desde soar-service). Se
  actualizaron las acciones block_ip/isolate_host de soar-service para que,
  solo cuando SOAR_DRY_RUN=false, deleguen en integration-service (que a su
  vez sigue en dry-run hasta que un operador configure un conector real) --
  cierra el ciclo dry-run-por-defecto en dos capas independientes, ninguna
  ejecuta nada real sin que un humano cambie explicitamente ambas variables
  de entorno Y configure un conector. Se agregaron report-service (8009),
  notification-service (8010) e integration-service (8011) a
  docker-compose.yml con el mismo patron de Dockerfile/build-context, y se
  actualizo el depends_on de frontend. Validado con py_compile (todo
  backend/, sin errores) y docker-compose.yml parseado como YAML valido con
  pyyaml (15 servicios).

- Pendiente: el token de GitHub usado por esta automatizacion no tiene permiso
  'Workflows', asi que el workflow de CI (.github/workflows/ci.yml) no se pudo
  subir. Si el usuario agrega ese permiso al token, una proxima corrida puede
  subirlo (esto se resuelve a fondo en la Fase 6, que cubre CI/CD). El frontend
  todavia no tiene vistas para activos/escaneos/vulnerabilidades/SIEM/SOAR/
  Casos/PurpleTeam/Reportes/Notificaciones/Integraciones -- esto esta
  contemplado para la Fase 6 (expansion del frontend). Ningun conector de
  firewall/EDR real esta configurado todavia en integration-service (ni
  deberia estarlo sin que el usuario/operador lo decida explicitamente) --
  la plataforma queda en modo 100% dry-run/simulado en ambas capas
  (SOAR_DRY_RUN e INTEGRATION_DRY_RUN) por defecto. Fase 6 (K8s, Terraform,
  CI/CD completo, expansion de frontend, documentacion final) queda
  pendiente para la proxima corrida.
