<h1 align="center">🛡️ TERO Security</h1>

<p align="center">
  <b>Self-hosted defensive security platform for small and mid-sized companies.</b><br>
  Asset inventory · Vulnerability management · SIEM · SOAR · Case management · MITRE ATT&CK coverage
</p>

<p align="center">
  <a href="https://github.com/Ridioortv/seginfo-toolkit/actions/workflows/ci.yml"><img src="https://github.com/Ridioortv/seginfo-toolkit/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-proprietary%20(EULA)-lightgrey" alt="License: proprietary EULA">
  <img src="https://img.shields.io/badge/Python-FastAPI-009688?logo=fastapi&logoColor=white" alt="Python FastAPI">
  <img src="https://img.shields.io/badge/React-TypeScript-3178C6?logo=react&logoColor=white" alt="React TypeScript">
  <img src="https://img.shields.io/badge/deploy-Docker%20%7C%20Kubernetes-2496ED?logo=docker&logoColor=white" alt="Docker and Kubernetes">
  <img src="https://img.shields.io/badge/i18n-ES%20%7C%20EN%20%7C%20ZH%20%7C%20RU-0F766E" alt="Languages">
</p>

<!-- Add a dashboard screenshot here once it exists:
<p align="center"><img src="docs/img/dashboard.png" alt="TERO Security dashboard" width="900"></p>
-->

---

TERO Security brings the core tools of a security operations center into a single platform that runs **on the customer's own infrastructure**. It discovers and inventories assets, orchestrates open-source scanners in **detection-only** mode, prioritizes findings with CVSS, EPSS and CISA KEV, correlates logs with Sigma rules, automates response through playbooks and tracks every incident until it is closed.

Built and sold by **[tecnoros.ar](https://www.tecnoros.ar)** (Rosario, Argentina).

## Features

**Visibility**
- **Asset inventory (CMDB)** with multi-organization support.
- **External attack surface monitoring** — passive subdomain discovery through Certificate Transparency and TLS certificate checks.
- **Cloud posture (AWS, read-only)** — imports EC2 and S3 inventory and flags public buckets and security groups open to `0.0.0.0/0`.
- **Code repository scanning** — committed secrets across the full git history (Gitleaks) and vulnerable dependencies (Trivy).

**Vulnerability management**
- Orchestrates **Trivy, Nuclei, OWASP ZAP, Semgrep, YARA, Zeek and Falco** in detection mode — never exploitation.
- Risk-based prioritization with **CVSS, EPSS and CISA KEV**, plus triage workflow.
- **Remote scan agent** for networks Docker Desktop cannot reach (LAN/WAN), authenticated with per-agent API keys.

**Detection & response**
- **SIEM** — log ingestion, normalization, **Sigma** rule correlation and alerting, with IP enrichment from **AbuseIPDB / MISP**.
- **SOAR** — automated playbooks (block IP, isolate host, open case), **dry-run by default**.
- **Case management** — ITSM-style incidents with per-priority SLAs and a full timeline.
- **Purple team metrics** — detection coverage mapped to **MITRE ATT&CK** with gap analysis.

**Operations**
- Executive and compliance **reports** built from data across all services.
- **Notifications** (email, Slack, webhook) and **containment integrations** (generic firewall/EDR), dry-run by default.
- **Authentication** with JWT, TOTP-based MFA, RBAC and Google sign-in.
- **UI in Spanish, English, Chinese and Russian.**
- **Subscription licensing** — a central server returns Ed25519-signed license status; payments via PayPal and Mercado Pago.

### Out of scope, by design

TERO Security is strictly **defensive**. It does **not** include C2 frameworks, exploit orchestration or any component that executes real attacks against targets. See [`docs/architecture.md`](docs/architecture.md) for the reasoning behind this boundary.

## Architecture

```
                         ┌──────────────────────────────┐
                         │  Frontend (React + TS, SPA)  │
                         └──────────────┬───────────────┘
                                        │ REST + JWT
   ┌──────────────┬──────────────┬──────┴───────┬──────────────┬──────────────┐
   │ auth         │ asset · asm  │ scan · vuln  │ siem · soar  │ case · purple│ ...
   │ (MFA, RBAC)  │ cloud · code │ (detection)  │ threatintel  │ report       │
   └──────┬───────┴──────┬───────┴──────┬───────┴──────┬───────┴──────┬───────┘
          └──────────────┴──── PostgreSQL · Redis · OpenSearch ───────┘

   remote-agent (optional, outside Docker)      licensing-server (operator-hosted)
```

| Service | Port | Responsibility |
|---|---|---|
| `auth-service` | 8001 | Identity, JWT, MFA (TOTP), RBAC, license check |
| `asset-service` | 8002 | Asset inventory (CMDB) |
| `scan-service` | 8003 | Scanner orchestration (detection only) |
| `vuln-service` | 8004 | CVSS / EPSS / CISA KEV prioritization and triage |
| `siem-service` | 8005 | Log ingestion, Sigma rules, alerts |
| `soar-service` | 8006 | Response playbooks (dry-run by default) |
| `case-service` | 8007 | Incidents, SLAs, timeline |
| `purple-service` | 8008 | MITRE ATT&CK coverage and gap analysis |
| `report-service` | 8009 | Executive and compliance reports |
| `notification-service` | 8010 | Email / Slack / webhook channels (dry-run by default) |
| `integration-service` | 8011 | Containment connectors (dry-run by default) |
| `threatintel-service` | 8012 | IP reputation lookups (AbuseIPDB, MISP) with caching |
| `asm-service` | 8013 | Passive external attack surface monitoring |
| `cloud-service` | 8014 | Read-only AWS inventory and misconfiguration checks |
| `coderepo-service` | 8015 | Secret and dependency scanning of code repositories |
| `frontend` | 5173 | React + TypeScript SOC-style dashboard |

All ports bind to `127.0.0.1` by default (`BIND_ADDR`).

## Quick start

**Requirements:** Docker with Docker Compose.

```bash
cp .env.example .env     # set your secrets
make up                  # Postgres, Redis, OpenSearch, 15 services + frontend
```

Then open **http://localhost:5173**.

| Command | What it does |
|---|---|
| `make up` / `make down` | Start / stop the stack |
| `make logs` | Follow service logs |
| `make test` | Run the test suites |
| `make lint` | Lint the codebase |
| `make migrate` / `make seed` | Apply migrations / load demo data |

**Windows, no command line:** a small Go launcher starts and stops the whole stack with a double click and opens the dashboard — see [`launcher/README.md`](launcher/README.md).

## Deployment

- **Local / on-prem:** `docker-compose.yml`.
- **Kubernetes:** Kustomize manifests in [`infra/k8s/base`](infra/k8s/base).
- **AWS:** Terraform skeleton in [`infra/terraform`](infra/terraform) — VPC, EKS, RDS, ElastiCache, OpenSearch, ECR.
- **Licensing server:** see [`licensing-server/README.md`](licensing-server/README.md).

## Security & quality

- **CI** on every push: backend tests (pytest per service), frontend typecheck and build, `docker compose` validation and image builds.
- **Security pipeline** on every PR and weekly: CodeQL, Bandit, pip-audit, npm audit, Trivy, Hadolint and Gitleaks.
- Pre-commit hook with secret scanning, Dependabot for dependencies, images and Actions.
- Hardened containers (`no-new-privileges`, least privilege) and a STRIDE threat model in [`docs/security.md`](docs/security.md).
- Found a vulnerability? Please report it privately — see [`SECURITY.md`](SECURITY.md).

## Documentation

Project documentation is written in Spanish.

| Document | Content |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Architecture and scope decisions |
| [`docs/security.md`](docs/security.md) | Threat model (STRIDE) |
| [`docs/security-hardening.md`](docs/security-hardening.md) | Hardening guide |
| [`docs/runbook.md`](docs/runbook.md) | Operations: startup, common incidents, enabling real SOAR actions, backups |
| [`STATUS.md`](STATUS.md) | Development status |

## License

TERO Security is **proprietary software** distributed under the end-user license agreement in [`LICENSE`](LICENSE). Third-party components keep their own licenses — see [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md), [`THIRD-PARTY-DEPENDENCIES.md`](THIRD-PARTY-DEPENDENCIES.md) and [`licenses/`](licenses/).

**Commercial inquiries:** [tecnoros.ar](https://www.tecnoros.ar) · [manuelangiulli11@gmail.com](mailto:manuelangiulli11@gmail.com)
