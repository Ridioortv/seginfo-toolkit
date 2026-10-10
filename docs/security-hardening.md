# Blindaje de seguridad (DevSecOps)

Estado del endurecimiento aplicado y lo que queda por hacer. Todo lo marcado como
**manual** requiere tu cuenta de GitHub o tu PC y no se puede automatizar desde el repo.

## Que se hizo

| Area | Cambio |
|---|---|
| Secretos en git | `.gitignore` ampliado (`.env*`, claves, tfstate, copias de clientes); `.env.bak` y `sentinel para sofi` fuera del indice; hook pre-commit (`.githooks/`) y `gitleaks` en CI frenan nuevas fugas. |
| Secretos locales | `tools/rotar-secretos.ps1` reemplaza JWT, clave de cifrado, password de Postgres y claves de agentes por valores aleatorios fuertes (sin imprimirlos). |
| Dependencias Python | `cryptography` 43→50, `python-jose` reemplazado por `PyJWT` 2.15 (GHSA-3qf3-8w2g-rqmx sin parche en python-jose; tambien elimina `ecdsa`, PYSEC-2026-1325), `python-multipart` 0.0.9→0.0.32, `requests` 2.32.3→2.34.2, `fastapi` 0.115→0.142 + `starlette` 0.38→1.7 (7 CVEs). Resultado `pip-audit`: 0 vulnerabilidades explotables. |
| Semgrep | Aislado en un venv propio dentro de la imagen de scan-service (sus pins viejos bloqueaban pydantic/FastAPI); actualizado a 1.179. |
| Tests | `pytest-asyncio` agregado a scan-service y siem-service: 7 tests async se saltaban en silencio. Ahora corren. |
| Frontend | Ya no corre el servidor de desarrollo de Vite como root: build estatico servido por nginx **sin privilegios** con CSP, X-Frame-Options, etc., sin secretos en el entorno. Vite 5→8, Vitest 2→5, React Router 6→7: `npm audit` 0 vulnerabilidades. |
| Docker | Puertos publicados solo en `127.0.0.1` (`BIND_ADDR` para cambiarlo); Postgres/Redis/OpenSearch nunca fuera de localhost; `no-new-privileges` en todo, `cap_drop: ALL` en las 12 APIs simples; `.dockerignore` raiz (el contexto de build ya no envia `.env` ni `.git`). |
| CI/CD | `security.yml`: gitleaks, bandit, pip-audit (con transitivas), npm audit, Trivy, hadolint, CodeQL y dependency-review. Acciones fijadas por SHA, `permissions: contents: read`, `persist-credentials: false`. Dependabot semanal para pip/npm/docker/gomod/actions. |
| Gobernanza | `SECURITY.md`, `CODEOWNERS`, plantilla de PR con checklist de seguridad. |
| Agentes | `agent.py` valida `SCAN_SERVICE_URL` (solo http/https) y avisa si la key viaja en claro hacia un host publico. |

## Manual (tu cuenta / tu PC)

0. Correr `tools\aplicar-github.ps1`: copia a `.github\` los workflows de CI/seguridad, Dependabot y CODEOWNERS (esa carpeta esta protegida contra escritura automatica, por eso las plantillas viven en `tools\github-templates\`).
1. **Revocar el token de GitHub** que estuvo en `.git/config`: <https://github.com/settings/tokens> (clasicos) y <https://github.com/settings/personal-access-tokens> (fine-grained).
2. Correr `tools\rotar-secretos.ps1` (secretos nuevos) y reiniciar el Agente LAN.
3. Correr `tools\github-blindaje.ps1` (activa secret scanning, push protection, Dependabot, proteccion de `main`).
4. Correr `tools\instalar-hooks.ps1` en cada PC donde se desarrolle.
5. Activar 2FA en GitHub (llave de seguridad o app).
6. Si el repo es publico y `.env.bak` llego a subirse: las claves de ese archivo ya se consideran expuestas; rotarlas (paso 2) las invalida. Purgar el historial (`git filter-repo` + force-push) es opcional y reescribe commits: hacelo solo si lo decidis.

## Riesgos conocidos y aceptados

- **scan-service** conserva capabilities elevadas (`NET_ADMIN`, `SYS_ADMIN`, `SYS_PTRACE`, ...) para zeek/falco (decision de producto). Es el contenedor mas privilegiado: no lo expongas fuera de localhost.
- **OpenSearch** corre con `DISABLE_SECURITY_PLUGIN=true` y **Redis** sin password: aceptable porque solo escuchan en la red interna de Docker y en `127.0.0.1`. Antes de exponerlos o desplegar en cloud, activar autenticacion y TLS.
- **Rate limiter** falla abierto: si Redis se cae, el login deja de limitar intentos (prioriza disponibilidad). Monitoreá Redis.
- **infra/terraform e infra/k8s** (plantillas de despliegue cloud) tienen hallazgos de Trivy (EKS publico, security contexts, egress abierto). No estan en uso; **corregirlas antes de desplegar a produccion**. El CI las reporta sin bloquear.
- Trafico entre navegador y APIs es HTTP en localhost. Para uso en red/internet poner un reverse proxy con TLS (`licensing-server/Caddyfile` es un ejemplo) y ajustar `connect-src` en `frontend/nginx.conf`.
