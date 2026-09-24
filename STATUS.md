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
- Fecha: 2026-09-24
- Tipo: mejora de calidad (las 6 fases planificadas ya estaban completas,
  ver corrida anterior). Ademas, esta corrida retomo trabajo de tests que
  habia quedado escrito en disco sin commitear por una corrida anterior
  interrumpida (probablemente por el mismo .git/index.lock colgado que se
  encontro y resolvio al arrancar esta corrida) -- se reviso y se corrio
  cada test antes de commitear, no se asumio que estuviera bien.
- Que se hizo:
  - Tests reales con pytest en los 4 servicios con logica pura facil de
    testear sin base de datos real: auth-service
    (tests/test_security.py, 11 tests: hashing/verificacion de password,
    creacion/decodificacion de JWT, generacion y verificacion de codigos
    TOTP), vuln-service (test_cvss.py + test_priority_score.py, 13
    tests: parseo de vector CVSS v3.1 y calculo del score de
    priorizacion combinando CVSS/EPSS/KEV), purple-service
    (test_coverage.py, 6 tests: gap-analysis de cobertura ATT&CK) y
    scan-service (test_nmap_driver.py, 6 tests: parseo de XML de nmap a
    findings normalizados). 36 tests en total. Cada servicio tiene su
    conftest.py (agrega el path del servicio y la raiz del repo a
    sys.path) y pytest==8.3.3 en requirements.txt (dependencia
    solo-de-test); los Dockerfile copian tests/ a la imagen y `make
    test` corre pytest en los 4 servicios via `docker compose exec`.
  - Frontend: se extrajo la logica de "esta vencido el SLA de este caso"
    de src/pages/Cases.tsx a una funcion pura testeable
    (src/utils/sla.ts::isSlaBreached) y se agregaron tests con vitest
    para ella y para el helper existente errors.ts::connectionErrorDetail
    -- 13 tests. Se agrego vitest a devDependencies, un script "test" a
    package.json, y vite.config.ts ahora usa defineConfig de
    "vitest/config" para declarar la config de test junto a la de vite.
  - Se corrigio docs/architecture.md: describia RabbitMQ y MinIO como
    parte de la arquitectura, pero la implementacion real (ver
    docker-compose.yml y el codigo) nunca uso ninguno de los dos -- la
    comunicacion entre servicios es HTTP/REST sincrono con JWT de
    servicio-a-servicio, y los reportes se guardan como blob en Postgres.
    Se actualizo el diagrama Mermaid y el texto para reflejar la
    arquitectura real.
  - .github/workflows/ci.yml: se agregaron pasos reales de pytest (los 4
    servicios con tests/) al job backend-smoke y de `npm run test --
    --run` (vitest) al job frontend-build, reemplazando comentarios TODO
    que decian "todavia no existen tests automatizados" -- ya no es
    cierto.
- Validacion antes de commitear: se instalaron las dependencias minimas
  de cada servicio (fastapi, sqlalchemy, asyncpg, pydantic, etc.) y se
  corrio `python3 -m pytest -q` real en los 4 servicios -- 11+6+6+13 =
  36 tests, todos en verde. `python3 -m py_compile` sobre todo backend/
  sin errores. ci.yml y docker-compose.yml parseados como YAML valido
  con PyYAML. Para el frontend no se pudo correr `npm install`/vitest en
  esta maquina: reaparecio el mismo problema de mount lento para
  node_modules ya documentado en la corrida de Fase 6 (`npm install` y
  hasta `ls node_modules` llegan a colgarse en esta maquina de
  automatizacion). En su lugar se valido con `tsc --noEmit` que
  sla.ts/sla.test.ts/errors.test.ts/Cases.tsx compilan sin errores de
  sintaxis (los unicos errores de tsc son en archivos no tocados aca, por
  falta de node_modules instalado, no bugs reales); el job
  frontend-build de GitHub Actions corre los tests de verdad en un
  runner limpio donde este problema no existe.

## Pendiente
- El token de GitHub usado por esta automatizacion sigue sin permiso
  'Workflows'. Si el push de esta corrida es rechazado por incluir
  cambios en .github/workflows/ci.yml, ese archivo queda escrito en
  disco sin commitear (igual que en la corrida de Fase 6) -- Manu puede
  agregarle al token el permiso 'Workflows: Read and write' (GitHub,
  Settings del fine-grained PAT) y subirlo el mismo desde su PC, o
  esperar a que una proxima corrida lo haga una vez tenga el permiso.
- La carpeta conectada de esta maquina de automatizacion tiene un mount
  lento para directorios con muchos archivos chicos (node_modules sobre
  todo) -- `npm install`/`ls node_modules`/`du` pueden colgarse. No
  afecta al repo ni al CI real (GitHub Actions corre en un runner
  limpio), solo a la validacion local en esta maquina.
- Cobertura de tests: auth-service, vuln-service, purple-service y
  scan-service ya tienen unit tests de su logica pura. Falta cobertura
  en asset-service, siem-service, soar-service, case-service,
  report-service, notification-service e integration-service, y tests
  de integracion/endpoint (con DB de test, ej. sqlite o testcontainers)
  para los servicios que ya tienen unit tests. Buen punto de partida
  para la proxima corrida de calidad.
- Ningun conector de firewall/EDR real esta configurado en
  integration-service (la plataforma sigue 100% dry-run por defecto,
  ver SOAR_DRY_RUN/INTEGRATION_DRY_RUN/NOTIFICATION_DRY_RUN) -- es
  intencional hasta que el usuario/operador lo decida explicitamente.
- infra/terraform sigue siendo un esqueleto de referencia, no aplicado
  contra ninguna cuenta de AWS real.
