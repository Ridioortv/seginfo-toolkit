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

## Cierre de calidad (2026-09-24, corrida especial "cierre a 100%")
Corrida adicional en la misma fecha, a pedido explicito de Manu, para
terminar la cobertura de tests que habia quedado a mitad de camino y
corregir lo que se encontrara roto -- no una fase nueva.

- Se instalaron las dependencias reales de los 4 servicios con tests
  (auth/purple/scan/vuln) y se corrio pytest de verdad: se encontro y
  corrigio un test flaky en auth-service
  (test_tampered_signature_is_rejected) -- tamperear el ULTIMO caracter
  de un JWT en base64url puede caer en un bit de padding no
  significativo y no cambiar el valor decodificado, dando un falso
  negativo. Se cambio a tamperear el PRIMER caracter de la firma, que
  siempre es significativo. Los otros 3 servicios ya estaban en verde.
- Se agregaron tests con pytest a los 7 servicios que todavia no
  tenian: asset-service (7, validacion de schemas), case-service (4,
  contrato de SLA_HOURS_BY_PRIORITY), integration-service (7, cifrado
  de credenciales de conector + dry-run), notification-service (9,
  validacion de canales + dry-run), report-service (8, exportacion
  CSV/PDF), siem-service (27, motor de reglas Sigma incluyendo que la
  evaluacion de `condition` este sandboxeada contra intentos de
  escape -- llamadas a funciones, acceso a atributos, imports -- y
  normalizacion ECS) y soar-service (13, ranking de severidad,
  resolucion de campos del contexto de una alerta, y dry-run). Mismo
  patron que los 4 servicios existentes: conftest.py + pytest en
  requirements.txt/Dockerfile. Total backend: 111 tests, todos en
  verde. Ahora los 11 microservicios backend tienen tests reales.
- Se corrigio `npm install` en el frontend: el node_modules de esta
  maquina tenia un zustand instalado de forma incompleta (faltaba
  esm/vanilla.d.mts, el archivo de tipos del que depende `create`) --
  no era un problema de mount lento como se penso en la corrida
  anterior, sino una instalacion corrupta de verdad. Se borro
  node_modules/package-lock.json y se reinstalo limpio. Eso destapo que
  `tsc --noEmit` (parte de `npm run build`) fallaba en TODO el frontend
  (9 errores de "implicitly has an 'any' type" en Layout/Billing/Login/
  Notifications/Organizations/SsoCallback/store/auth.ts) porque
  store/auth.ts llamaba a `create<AuthState>((set) => ...)` sin la
  forma "curried" que zustand 4 necesita para inferir bien el tipo de
  `set` (`create<AuthState>()((set) => ...)`). Se corrigio esa unica
  linea y los 9 errores desaparecieron. `npm run build` y `npx tsc
  --noEmit` quedan limpios de verdad, verificado en esta corrida (no
  solo con esbuild como aproximacion, como en la corrida anterior).
- Se agregaron mas tests de frontend: se extrajo la logica de
  interpretacion del error 402 de pago vencido de Login.tsx a una
  funcion pura (src/utils/loginError.ts::parseLoginError, 8 tests) y el
  formateo de fecha de Billing.tsx a src/utils/format.ts::formatDate (4
  tests) -- mismo patron que sla.ts. Frontend: 25 tests en total (antes
  13), todos en verde. No se agrego @testing-library/react en esta
  corrida (requeriria cambiar test.environment de "node" a "jsdom" y
  nuevas dependencias) -- queda como posible proximo paso si Manu quiere
  tests que rendericen componentes, no solo la logica pura que ya usan.
- Se corrigio docs/security.md: la fila de la tabla STRIDE sobre
  "no hay multi-tenant todavia" estaba desactualizada -- el
  multi-tenant por fila (organization_id) ya esta implementado en todos
  los servicios desde hace varias corridas. Se corrigio para reflejar
  el estado real.
- .github/workflows/ci.yml sigue sin poder commitearse (ver Pendiente).

## Pendiente -- decision de Manu, no es codigo
- [RESUELTO 2026-09-24] Manu le agrego el permiso 'Workflows: Read and
  write' al fine-grained PAT y .github/workflows/ci.yml ya esta
  commiteado y pusheado -- el job backend-smoke se actualizo para
  correr pytest en los 11 servicios (antes solo cubria los 4 que tenian
  tests en ese momento). CI corriendo en GitHub Actions desde el commit
  c1557db.
- Falta decidir el registry para publicar las imagenes Docker (GHCR es
  la opcion mas simple, no requiere credenciales de AWS) y agregar el
  login+push al job docker-build -- hoy ese job solo verifica que cada
  Dockerfile buildea, no publica nada.
- Ningun conector de firewall/EDR real esta configurado en
  integration-service (la plataforma sigue 100% dry-run por defecto,
  ver SOAR_DRY_RUN/INTEGRATION_DRY_RUN/NOTIFICATION_DRY_RUN) -- es
  intencional hasta que el usuario/operador lo decida explicitamente.
- infra/terraform sigue siendo un esqueleto de referencia, no aplicado
  contra ninguna cuenta de AWS real -- revisar costos, security groups
  y backend remoto de estado antes de un uso real (ver
  infra/terraform/README.md).
- Cobertura de tests que podria seguir creciendo (no bloqueante): tests
  de integracion/endpoint con DB de test (sqlite o testcontainers) para
  los 11 servicios -- hoy todos tienen unit tests de su logica pura,
  pero ninguno tiene un test que levante la app FastAPI completa contra
  una base real. Tests de frontend que rendericen componentes (con
  @testing-library/react) en vez de solo la logica pura extraida a
  utils/.

## Cierre del pedido de funcionalidades "100% funcional por botones" (2026-09-24)
Corrida a pedido explicito de Manu: hacer que Activos, Escaneos,
Vulnerabilidades, SIEM, SOAR, Casos, Purple Team, Reportes,
Notificaciones e Integraciones queden completas y usables con botones
(sin JSON/codigo a mano), y agregar una guia de uso dentro de la app.
Ejecutada en 10 fases, cada una commiteada y pusheada por separado:

- Activos: alta de activos + boton "Escanear (detectar fallos)" por
  fila que lanza un scan-job real contra ese activo.
- Escaneos: borrado por item de escaneos y agent-scans ya terminados
  (`DELETE /scans/{id}`, `DELETE /agent-scans/{id}`, solo en estados
  terminales).
- Vulnerabilidades: pasos de remediacion generados por reglas
  (`vuln-service/app/remediation.py`, sin IA/red) mostrados por fila +
  triage (confirmado/falso positivo/riesgo aceptado/remediado).
- SIEM: severidad agregada al esquema ECS-lite, 3 reglas Sigma
  recomendadas seedeables con un boton, y creador de reglas 100% por
  formulario (sin JSON a mano). Los hallazgos de scan-service ahora se
  forwardean tambien a SIEM (antes solo a vuln-service).
- SOAR: borrado de playbooks + creador de pasos de playbook por
  formulario (accion + parametros), sin textarea de JSON.
- Casos: sincronizacion automatica periodica con SOAR
  (`case-service::_soar_sync_loop`, mismo patron que
  `auth-service::_license_check_loop`) + gestion completa por botones
  (tomar/resolver/cerrar/reabrir, asignar, notas).
- Purple Team: declaracion de ejercicios por checklist de tecnicas
  ATT&CK + recalculo de cobertura y vista de gaps, todo por UI.
- Reportes: borrado de reportes generados por item.
- Notificaciones: dashboard + habilitar/deshabilitar/borrar canales.
- Integraciones: formularios estructurados por tipo de conector
  (firewall/EDR, ticketing) en vez de un textarea de config JSON.
- Ayuda: seccion nueva (`/help`), visible para todos los roles, con
  guia interactiva en espanol simple de cada funcion de la plataforma,
  busqueda de texto libre y progreso de lectura persistido en el
  navegador (mas una subseccion solo-admin para Organizaciones y pagos).

Validacion: cada fase se verifico con pytest real de los servicios
backend tocados, `tsc --noEmit`, `vitest run` y `npm run build` del
frontend antes de commitear -- todo en verde en las 10 fases.
