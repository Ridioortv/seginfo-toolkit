# Arquitectura — SentinelOps

## Vision general

Microservicios independientes (FastAPI) detras de un API gateway, con un frontend
SPA en React/TypeScript. Cada servicio tiene su propia base de datos logica dentro
de Postgres y se comunica de forma asincrona via RabbitMQ cuando corresponde.

## Diagrama

\`\`\`mermaid
flowchart TB
    subgraph Cliente
        FE[Frontend React/TS<br/>Dashboard SOC]
    end

    subgraph Backend
        AUTH[auth-service<br/>JWT + MFA + RBAC]
        ASSET[asset-service<br/>CMDB]
        SCAN[scan-service<br/>orquestacion escaneres]
        VULN[vuln-service<br/>CVSS/EPSS/KEV]
        SIEM[siem-service<br/>ingesta + correlacion]
        SOAR[soar-service<br/>playbooks]
        CASE[case-service<br/>incidentes]
        PURPLE[purple-service<br/>gap analysis]
        REPORT[report-service<br/>PDF/HTML]
        NOTIF[notification-service]
        INTEG[integration-service]
    end

    subgraph Datos
        PG[(PostgreSQL)]
        REDIS[(Redis)]
        OS[(OpenSearch)]
        MQ[(RabbitMQ)]
        MINIO[(MinIO)]
    end

    FE --> AUTH
    FE --> ASSET
    FE --> SCAN
    FE --> VULN
    FE --> SIEM
    FE --> SOAR
    FE --> CASE
    FE --> PURPLE
    FE --> REPORT

    SCAN --> VULN
    SIEM --> SOAR
    SOAR --> CASE
    PURPLE --> SIEM

    AUTH --> PG
    ASSET --> PG
    VULN --> PG
    CASE --> PG
    SIEM --> OS
    SCAN --> MQ
    SOAR --> MQ
    REPORT --> MINIO
    AUTH --> REDIS
\`\`\`

## Fuera de alcance (deliberado)

Este proyecto no implementa, y no va a implementar en fases futuras:

- Frameworks de C2 (Sliver, Mythic, Cobalt Strike o similares)
- Orquestacion de herramientas de explotacion (Metasploit, SQLmap en modo ataque)
- Tracking de "operaciones red team" como ejecucion de intrusion real
- Cualquier mecanismo que automatice un ataque contra un objetivo real

El modulo "purple team" se limita a: dado un conjunto de tecnicas MITRE ATT&CK
declaradas (importadas como datos, no ejecutadas), calcular que reglas de
deteccion SIEM las cubren y reportar gaps. Es analisis sobre datos, no ejecucion.

## Servicios por fase

Ver `STATUS.md` en la raiz del repo para el detalle fase por fase.
