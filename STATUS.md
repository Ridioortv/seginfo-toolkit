# Estado del proyecto SentinelOps (seginfo-toolkit)

Alcance: plataforma de ciberseguridad DEFENSIVA (SIEM/SOAR, gestion de vulnerabilidades
en modo escaneo, gestion de casos, cumplimiento, reportes, dashboard). No incluye
motores de ejecucion ofensiva ni integracion C2 (ver docs/architecture.md, seccion
"Fuera de alcance").

## Fases
- [x] Fase 1: Arquitectura + docker-compose + estructura + auth-service + frontend base
- [x] Fase 2: asset-service + scan-service (orquestacion de escaneres defensivos) + vuln-service
- [ ] Fase 3: siem-service + soar-service
- [ ] Fase 4: case-service + purple-service (metricas/gap-analysis, sin motor ofensivo)
- [ ] Fase 5: report-service + notification-service + integration-service
- [ ] Fase 6: K8s + Terraform + CI/CD completo + documentacion final

## Ultima corrida
- Fecha: 2026-09-22
- Fase completada: 2
- Proxima fase: 3
- Notas: asset-service (inventario/CMDB de activos), scan-service (orquestacion de
  Nmap/Trivy/Nuclei/OpenVAS -- todos los drivers en modo SOLO DETECCION, sin
  scripts/plantillas de explotacion, ver app/scanners/base.py y cada driver) y
  vuln-service (CVSS, enriquecimiento EPSS/CISA KEV, priorizacion y workflow de
  triage de falsos positivos). scan-service reenvia hallazgos a vuln-service para
  ingesta automatica. Los tres servicios sumados a docker-compose.yml siguiendo el
  patron de auth-service (Dockerfile con build context en la raiz, copiando
  backend/shared). Validado con py_compile (30 archivos, sin errores de sintaxis)
  y `docker-compose.yml` verificado como YAML valido (docker no disponible en esta
  maquina de automatizacion para correr `docker compose config`).
- Pendiente: el token de GitHub usado por esta automatizacion no tiene permiso
  'Workflows', asi que el workflow de CI (.github/workflows/ci.yml) no se pudo subir.
  Si el usuario agrega ese permiso al token, una proxima corrida puede subirlo
  (esto se resuelve a fondo en la Fase 6, que cubre CI/CD). El frontend todavia no
  tiene vistas para activos/escaneos/vulnerabilidades -- esto esta contemplado
  para la Fase 6 (expansion del frontend).
