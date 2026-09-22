# SentinelOps (seginfo-toolkit)

Plataforma de ciberseguridad defensiva: gestion de activos, escaneo de vulnerabilidades,
SIEM/SOAR, gestion de casos, purple team (metricas de deteccion) y reportes de
cumplimiento. Pensada para vender a empresas como producto propio.

## Alcance

Este proyecto cubre exclusivamente el lado DEFENSIVO de una plataforma de seguridad:

- Inventario de activos (CMDB)
- Orquestacion de escaneres de vulnerabilidades (Nmap, Trivy, Nuclei, OpenVAS) en modo
  deteccion — nunca explotacion
- Priorizacion con CVSS / EPSS / CISA KEV
- SIEM: ingesta, normalizacion, correlacion de reglas Sigma, alertas
- SOAR: playbooks de respuesta automatizada (bloquear IP, aislar host, abrir caso)
- Gestion de casos e incidentes (estilo ITSM)
- Purple team: mapeo de cobertura de deteccion contra MITRE ATT&CK y gap analysis
  (analisis y metricas — sin motor de ejecucion de tecnicas ofensivas ni integracion C2)
- Reportes de cumplimiento (ISO 27001, NIST CSF, PCI-DSS) y dashboards ejecutivos

Deliberadamente NO incluye: frameworks C2, orquestacion de exploits, o cualquier
componente que ejecute ataques reales contra objetivos. Ver `docs/architecture.md`
para el detalle de arquitectura y el motivo de este recorte.

## Estado de avance

Ver [`STATUS.md`](./STATUS.md) — el proyecto se construye en fases, una por dia,
mediante una tarea programada.

## Arranque local

\`\`\`bash
cp .env.example .env
make up
\`\`\`

Esto levanta Postgres, Redis, el auth-service (puerto 8001) y el frontend (puerto 5173).

## Estructura

\`\`\`
backend/
  shared/            # utilidades comunes (db, seguridad, logging)
  services/
    auth-service/    # identidad, JWT, MFA (TOTP), RBAC
frontend/            # SPA React + TypeScript, dashboard oscuro tipo SOC
docs/                # arquitectura y documentacion
\`\`\`
