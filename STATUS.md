# Estado del proyecto SentinelOps (seginfo-toolkit)

Alcance: plataforma de ciberseguridad DEFENSIVA (SIEM/SOAR, gestion de vulnerabilidades
en modo escaneo, gestion de casos, cumplimiento, reportes, dashboard). No incluye
motores de ejecucion ofensiva ni integracion C2 (ver docs/architecture.md, seccion
"Fuera de alcance").

## Fases
- [x] Fase 1: Arquitectura + docker-compose + estructura + auth-service + frontend base
- [ ] Fase 2: asset-service + scan-service (orquestacion de escaneres defensivos) + vuln-service
- [ ] Fase 3: siem-service + soar-service
- [ ] Fase 4: case-service + purple-service (metricas/gap-analysis, sin motor ofensivo)
- [ ] Fase 5: report-service + notification-service + integration-service
- [ ] Fase 6: K8s + Terraform + CI/CD completo + documentacion final

## Ultima corrida
- Fecha: 2026-09-22
- Fase completada: 1
- Proxima fase: 2
- Notas: repo inicializado, auth-service con JWT + TOTP scaffold, frontend Vite+React
  con login funcional contra auth-service, docker-compose con postgres/redis/auth/frontend.
- Pendiente: el token de GitHub usado por esta automatizacion no tiene permiso
  'Workflows', asi que el workflow de CI (.github/workflows/ci.yml) no se pudo subir.
  Si el usuario agrega ese permiso al token, la siguiente corrida puede subirlo
  (esto se resuelve a fondo en la Fase 6, que cubre CI/CD).
