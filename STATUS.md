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

## Corrida de calidad (2026-09-26)

Las 6 fases planificadas ya estaban completas (ver arriba) y la corrida anterior
(2026-09-25) agrego el stack real de OpenVAS/GVM + el agente de escaneo remoto,
asi que esta corrida se dedico a verificacion y a cerrar una brecha de
documentacion que encontro, sin tocar codigo de los servicios:

- **Verificacion completa**: se corrio pytest real (no solo `py_compile`) en
  los 11 servicios backend con el venv compartido `backend/.venv` -- 182 tests,
  todos en verde (auth 11, asset 7, scan 52, vuln 20, case 9, integration 7,
  notification 9, report 14, siem 34, soar 13, purple 6). En el frontend,
  `npm run test -- --run` (35 tests, todos en verde) y `npx tsc --noEmit`
  (limpio, cero errores). `docker-compose.yml` se valido como YAML bien
  formado con PyYAML (no hay Docker en esta maquina de automatizacion para
  correr `docker compose config` de verdad -- eso ya lo cubre el job
  `compose-validate` de CI en un runner con Docker). Se reviso `.env.example`
  contra las variables que usa `docker-compose.yml`: todo esta declarado. Se
  busco `TODO`/`FIXME`/`XXX` en todo `backend/` y `frontend/src`: no hay
  ninguno real (los dos matches en backend son falsos positivos de texto,
  "tXXXX" de una convencion de tags ATT&CK y la palabra "TODOS" en espanol).
- **Brecha de documentacion encontrada y corregida**: la corrida del
  2026-09-25 agrego ~15 servicios del stack GVM/OpenVAS y el
  `remote-agent/` opcional al `docker-compose.yml`, pero `docs/architecture.md`
  y `docs/security.md` nunca se actualizaron para reflejarlo -- quedaban
  describiendo solo los 11 microservicios originales. Se agrego a
  `docs/architecture.md` una seccion nueva ("Componentes agregados fuera de
  los 11 microservicios") explicando el stack GVM (por que son ~15 servicios,
  que red Docker aislada usan, por que `ospd-openvas` necesita capacidades de
  red elevadas) y el `remote-agent` (que problema resuelve, modelo de
  autenticacion). Se agregaron dos filas a la tabla STRIDE de
  `docs/security.md`: en Spoofing, el modelo de autenticacion del
  remote-agent (API key propia, solo se persiste el hash, nunca la key en
  claro); en Elevation of Privilege, la elevacion real de `ospd-openvas`
  (`NET_ADMIN`/`NET_RAW` + seccomp/apparmor sin confinar) con su mitigacion
  (red Docker `gvm_internal` aislada sin salida a internet ni camino hacia el
  resto de la plataforma, comunicacion por socket unix en vez de red,
  `no-new-privileges`) y el pendiente (evaluar un perfil seccomp scoped si
  Greenbone lo publica, o aislar ese contenedor en un host separado para
  clientes con requisitos mas estrictos). Estos detalles ya estaban
  documentados como comentarios en linea en `docker-compose.yml` (de la
  corrida anterior) -- este cambio los sube al modelo de amenazas formal,
  que es donde alguien evaluando el producto realmente los va a buscar.
- No se toco codigo de ningun servicio: no hizo falta ningun fix, todo lo
  que se corrio ya estaba en verde.

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

## Escaneres: nmap/trivy/nuclei mas rapidos + OpenVAS real (2026-09-25)

Pedido de Manu: "los scaneres... todos tardan mucho y openvas no anda directamente".

- **nmap**: nuevo modo `fast`/`full` (toggle en "Nuevo escaneo" en la UI).
  `full` es el comportamiento historico (-sV -sC --script default,safe,
  timeout 180s). `fast` saca los scripts NSE (el mayor costo de tiempo),
  se queda con -sV, limita a --top-ports 100 si no se especifican puertos,
  y usa timeout 60s. Guardrail de scope (`_ALLOWED_EXTRA_FLAGS`) sin tocar.
- **trivy**: la DB de CVEs se bajaba en CADA escaneo. Ahora se descarga
  una vez al construir la imagen (Dockerfile) y se persiste en el volumen
  `trivy_cache`; el driver corre con `--skip-db-update`; un job periodico
  (`refresh_trivy_db`, cada 24hs via APScheduler) la mantiene actualizada
  en segundo plano. Fallback automatico a descarga si la cache esta vacia
  (primer arranque antes de que corra el refresh).
- **nuclei**: mismo problema con las plantillas -- se bajan una vez al
  construir la imagen, se persisten en `nuclei_templates`, el driver corre
  con `-duc` (disable update check), y `refresh_nuclei_templates` las
  actualiza cada 12hs en segundo plano.
- **OpenVAS**: antes no estaba instalado, y el driver ni siquiera se
  autenticaba ni disparaba un escaneo (solo hacia una consulta sin auth).
  Ahora es un stack GVM (Greenbone Community Edition) real:
  `docker-compose.yml` agrega ~16 servicios (feeds de NVTs, postgres
  propio de GVM, gvmd, openvas-scanner, ospd-openvas -- sin la GUI web
  gsa/gsad/nginx, que no hace falta para esto). `scan-service` habla con
  gvmd via `gvm-cli` (paquete pip `gvm-tools`, agregado a su Dockerfile)
  por el socket montado de gvmd. El driver nuevo
  (`app/scanners/openvas.py`) hace el flujo GMP completo: descubre
  dinamicamente config/scanner/port_list (no hardcodea UUIDs -- pueden
  faltar en instalaciones nuevas), crea target+task, lo arranca, hace
  poll hasta que termina (o timeout, `GVM_SCAN_TIMEOUT_SECONDS`, default
  1500s) y trae los resultados reales.

### Pasos manuales que le tocan a Manu (no puedo correr Docker desde aca)

1. `docker compose build` (va a tardar mas que antes: ahora tambien
   baja la DB de trivy y las plantillas de nuclei al construir la
   imagen de scan-service) y despues `docker compose up -d`.
2. **Primera sincronizacion del feed de GVM**: los contenedores
   `vulnerability-tests`, `notus-data`, `scap-data`, etc. bajan el feed
   completo de NVTs/CVEs de Greenbone la primera vez -- puede tardar
   **horas** y ocupar **varios GB** de disco. `docker compose logs -f
   gvmd` para ver el progreso; gvmd no queda realmente usable hasta que
   terminen.
3. **Bootstrap del usuario admin de GVM** (una sola vez, despues de que
   gvmd este arriba):
   ```
   docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='TU_PASSWORD_ACA'
   ```
   Despues completar `GVM_USER=admin` y `GVM_PASSWORD=TU_PASSWORD_ACA`
   en `.env` (mismo valor que se paso arriba) y reiniciar scan-service
   (`docker compose restart scan-service`).
4. **Nota de seguridad -- ospd-openvas (actualizado 2026-09-26)**: el
   servicio `ospd-openvas` corre con `cap_add: [NET_ADMIN, NET_RAW]` y
   `security_opt: [seccomp=unconfined, apparmor=unconfined]`. Esto NO se
   puede sacar: el motor openvas-scanner arma paquetes crudos el mismo
   (sockets raw, ICMP, IP_HDRINCL) para descubrimiento/fingerprinting de
   host, y esos syscalls estan bloqueados por el perfil seccomp default
   de Docker y por AppArmor -- asi lo requiere el propio compose oficial
   de Greenbone, sin un perfil scoped alternativo documentado. Sacarlo
   rompe el escaner.

   Lo que si se hizo para achicar el impacto si ESE contenedor puntual
   se ve comprometido (sin tocar esas dos capacidades, que son las que
   de verdad hacen falta):
   - `security_opt: no-new-privileges:true` -- bloquea escalar privilegios
     via setuid/setgid en cualquier binario que corra adentro.
   - Red Docker propia `gvm_internal` (`internal: true`, sin salida a
     internet) para TODO el stack GVM/OpenVAS -- ningun otro servicio de
     SentinelOps (postgres, redis, el resto de los microservicios)
     comparte esa red. `scan-service` no la necesita: habla con `gvmd`
     por el socket unix montado (`gvmd_socket_vol`), no por red. Asi,
     aunque `ospd-openvas` se vea comprometido, no tiene ningun camino de
     red hacia el resto de la plataforma.
   - Se evaluo `cap_drop: [ALL]` (dejar solo NET_ADMIN/NET_RAW en vez de
     heredar todo el set default de Docker encima) pero quedo afuera a
     proposito: no puedo levantar el contenedor desde aca para confirmar
     que el entrypoint de la imagen no necesita algun otro capability
     (ej. CHOWN/SETUID al arrancar) -- romper el arranque a ciegas es
     peor que dejar el mismo set que testea el compose oficial. Si
     despues de que este todo andando lo queres mas restrictivo, se
     puede probar `cap_drop: [ALL]` como cambio aislado y ver si el
     contenedor sigue arrancando bien.
5. Si algo falla al levantar el stack o al lanzar un escaneo OpenVAS,
   mandame los logs (`docker compose logs scan-service gvmd
   ospd-openvas`) para poder iterar -- no puedo ver los contenedores
   corriendo desde aca.

Validacion hecha desde aca: 52 tests de pytest en scan-service (nmap +
trivy + nuclei + openvas, todos como funciones puras sin I/O real) en
verde. No pude correr `docker compose build/up` (sin acceso a Docker en
este entorno) -- eso queda pendiente de que Manu lo corra y reporte.

## Auditoria funcional completa + 17 bugs corregidos (2026-09-26)

Pedido de Manu: "testeá toda la aplicación y arreglá lo que no anda". Se armo
un brief de auditoria profesional (metodologia: leer cada endpoint/pagina real,
rastrear cada boton hasta la DB y de vuelta, buscar RBAC/multi-tenancy roto,
dry-run mal aplicado, errores no manejados) y se corrio en 5 grupos en paralelo,
cada uno cubriendo un area de la plataforma, sin superposicion de archivos.
Ningun grupo hizo commit por su cuenta -- se reviso y se consolido todo en un
solo commit despues de correr los 204 tests backend + 41 tests frontend +
tsc + build, todo en verde.

**Bug critico de seguridad (auth-service)**: `POST /auth/mfa/enroll` permitia
reemplazar el secret de MFA de un usuario que YA tenia MFA activo sin pedir
ninguna prueba de que quien llamaba controlaba el dispositivo ya enrolado --
alcanzaba con un access_token valido (15 min, robable via XSS/log/dispositivo
prestado) para secuestrar el segundo factor de otra cuenta sin conocer su TOTP
ni su contrasena, y la victima no veia ninguna señal (mfa_enabled seguia en
True todo el tiempo). Ahora re-enrolar exige un TOTP valido del secret actual.

**Otros bugs reales corregidos** (17 en total, detalle completo en el historial
de commits): notas de analista borradas silenciosamente al cambiar el estado de
una alerta SIEM (siem-service); un job de escaneo que quedaba en "running" para
siempre si el driver tiraba una excepcion no prevista (scan-service); un agente
remoto podia pisar el resultado de un job ya terminado (scan-service); un
analyst podia desactivar un activo por PATCH esquivando la restriccion de rol
del DELETE (asset-service); el dashboard ejecutivo mostraba "0 alertas/casos"
en vez de distinguir "vacio" de "servicio caido" (Dashboard.tsx); reabrir un
caso no limpiaba `resolved_at`, dejando metricas de MTTR con datos viejos
(case-service); un ejercicio Purple Team sin tecnicas declaradas calculaba
cobertura contra TODO el catalogo ATT&CK en vez de reportar 0 (purple-service);
registro de acciones de playbook duplicado y desincronizado, le faltaban
`create_ticket`/`notify` a una de las dos copias (soar-service); botones
CSV/PDF de Reportes fallaban en silencio absoluto sin ningun mensaje de error
(Reports.tsx); `HTTPException` no importado en notification-service e
integration-service (un 404 esperado se convertia en 500 sin manejar); registro
exitoso mostrado como fallido si el login automático posterior fallaba
(Login.tsx); formulario de SSO y pantallas de facturacion arrastraban datos de
la organizacion anterior al cambiar de organizacion elegida (Organizations.tsx,
Billing.tsx); mutations sin `onError` en Siem.tsx/Soar.tsx (seedDefaults, panel
de ejecuciones).

**Cosas senaladas pero NO tocadas** (dudas explicitas de los agentes, no
"arregladas a ciegas"): posible condicion de carrera en el hash chain del audit
log de auth-service sin lock a nivel DB; `validate_id_token` (SSO/OIDC) confia
en el `alg` del header del id_token en vez de una whitelist fija (mitigado por
la libreria instalada, pero no es la practica mas correcta); contador
Prometheus `alerts_created_total` que nunca se incrementa de verdad (bug de
observabilidad, no afecta la UI); doble entrada de timeline en cada cambio de
estado de un caso; exportacion XLSX mencionada en el alcance original pero
nunca implementada (solo CSV/PDF) -- gap de alcance, no bug de comportamiento.

Verificacion: 204 tests de pytest (auth 16, asset 11, scan 60, vuln 20, case 15,
integration 8, notification 10, report 14, siem 39, soar 14, purple 11) + 41
tests de vitest + `tsc --noEmit` limpio + `npm run build` exitoso, todo en
verde antes de commitear.

## Nueva funcionalidad: Monitoreo de superficie externa + Inteligencia de amenazas (2026-09-26)

Pedido de Manu: de la lista de 8 funcionalidades nuevas propuestas, arrancar
por "Empresa con el 1 luego 2 luego 3" -- es decir, primero Monitoreo de
superficie externa + Inteligencia de amenazas, despues integraciones cloud
(AWS primero), despues escaneo de codigo/repositorios. El asistente con IA
queda pospuesto: Manu todavia no tiene API key de Anthropic para esa parte.

Se construyeron 2 microservicios nuevos en paralelo (sin superposicion de
archivos: cada uno con su directorio propio + una pagina de frontend nueva
exclusiva; `docker-compose.yml`/`.env.example`/`api.ts`/`types.ts`/
`Layout.tsx`/`App.tsx` quedaron fuera del alcance de ambos agentes y se
consolidaron centralmente despues).

**`threatintel-service` (puerto 8012)**: consulta reputacion de IPs contra
AbuseIPDB (y opcionalmente MISP) con cache de 24hs en `IpReputationCache`
(sin `organization_id` -- la reputacion de una IP es un hecho global, no de
tenant). Sin `ABUSEIPDB_API_KEY` configurada, nunca llama a la API externa
(para no gastar el cupo del free tier, 1000/dia) y devuelve directamente "no
se pudo chequear". `siem-service` ahora enriquece automaticamente cada alerta
nueva: extrae las IPs del evento que la disparo, les pregunta a
threatintel-service (`POST /internal/lookup-batch`, sin auth de usuario --
solo alcanzable dentro de la red interna, mismo patron que el resto de
`/internal/*`), y guarda en `Alert.threat_intel` solo las que resultaron
maliciosas conocidas. Todo con el mismo patron best-effort ya usado para
SOAR (`httpx.HTTPError` atrapado, nunca tumba la ingesta de logs). En el
frontend, la pagina SIEM ahora tiene un buscador manual de IP y una columna/
badge de Threat Intel en la tabla de alertas.

**`asm-service` (puerto 8013)**: monitoreo de superficie externa 100% pasivo
-- sin escaneo activo de puertos en ningun lado. Cada dominio que se agrega
via `POST /domains` se chequea automaticamente cada `ASM_CHECK_INTERVAL_HOURS`
horas (default 12): descubre subdominios nuevos consultando Certificate
Transparency logs (`crt.sh`, solo GET a registros publicos ya existentes) y
lee el certificado TLS de cada host expuesto (handshake estandar al puerto
443, sin validar la cadena, solo para poder leer certificados vencidos o
autofirmados sin que la lectura falle). Genera alertas automaticas
(`SurfaceAlert`) cuando aparece un subdominio nuevo o cuando un certificado
esta vencido o vence en <=7 dias (critico/alto) o <=30 dias (medio), con
cooldown de 24hs para no duplicar la misma alerta. Las alertas de severidad
alta/critica tambien se reenvian a siem-service. Nueva pagina de frontend
"Superficie Externa" (nav, entre Escaneos y Vulnerabilidades): alta de
dominios, tabla de dominios monitoreados con boton "Chequear ahora", tabla de
subdominios descubiertos, tabla de alertas con filtro pendiente/todas.

**Limitaciones conocidas** (documentadas por el equipo que lo construyo, no
son bugs): borrar un dominio monitoreado no borra en cascada sus activos/
alertas historicas (a proposito, para no perder historial); hay una ventana
de carrera sin impacto real si se deshabilita un dominio justo despues de
pedir "chequear ahora"; la lectura de certificados autofirmados/con cadena
rota depende de que el modulo `cryptography` este disponible como fallback
(ya viene instalado transitivamente) -- si fallara, se reporta un error
explicito en vez de fallar mudo.

**Paso manual pendiente para Manu**: conseguir una API key de AbuseIPDB
(gratis, https://www.abuseipdb.com/account/api, 1000 consultas/dia) y
pegarla en `ABUSEIPDB_API_KEY` del `.env` si quiere que threatintel-service
haga chequeos reales -- sin eso, la funcionalidad sigue andando pero siempre
devuelve "no se pudo chequear". MISP es opcional. Como siempre, correr
`docker compose build && docker compose up` para levantar los servicios
nuevos (no se puede correr Docker desde este entorno).

Verificacion antes de commitear: 21 tests nuevos en threatintel-service + 23
en asm-service + 48 en siem-service (40 preexistentes + 8 nuevas de
enriquecimiento), todos funciones puras sin I/O real; import de humo de
`app.main` en ambos servicios nuevos (rutas registradas OK); 41 tests de
vitest + `tsc --noEmit` limpio + `npm run build` exitoso en el frontend
completo.

## Nueva funcionalidad: Integraciones cloud, AWS (2026-09-26)

Segunda de las 8 funcionalidades pedidas por Manu, priorizada como #2 ("Empresa
con el 1 luego 2 luego 3", ya con superficie externa + threat intel hechos).
AWS primero (Azure/GCP quedan para mas adelante, no se tocan en este cambio).

**`cloud-service` (puerto 8014)**: trae automaticamente el inventario de una
cuenta de AWS (instancias EC2, buckets S3, security groups) en lugar de
cargarlo a mano, y detecta configuraciones peligrosas: buckets S3 publicos y
security groups con puertos abiertos a `0.0.0.0/0`. 100% de solo lectura hacia
AWS -- todas las llamadas son `Describe*`/`List*`/`Get*`, nunca se crea,
modifica ni borra nada en la cuenta del cliente. Sync automatico cada
`CLOUD_SYNC_INTERVAL_HOURS` horas (default 6) sobre todas las cuentas
habilitadas de todas las organizaciones; una cuenta con credenciales invalidas
o una llamada que falla (ej. `AccessDenied` en un bucket puntual) nunca frena
el sync del resto.

Las credenciales de AWS (`access_key_id`/`secret_access_key`) se cifran en la
base con el mismo mecanismo ya usado para SSO/conectores
(`backend/shared/crypto.py`, Fernet derivado de `ENCRYPTION_KEY`) y nunca se
devuelven por la API en texto plano ni cifradas -- solo una version enmascarada
del access key (`AKIA...WXYZ`). Los hallazgos de severidad alta/critica se
reenvian a siem-service con el mismo patron best-effort ya usado por
asm-service/scan-service.

Nueva pagina de frontend "Integraciones Cloud" (nav, junto a "Superficie
Externa"): conectar cuenta de AWS (con la politica IAM de solo lectura exacta
documentada en el formulario), tabla de cuentas conectadas con estado del
ultimo sync y boton "Sincronizar ahora", tabla de recursos descubiertos, tabla
de hallazgos peligrosos con filtro pendiente/todos y boton "Reconocer".

**Paso manual pendiente para Manu**: crear en AWS un usuario/rol IAM de SOLO
LECTURA con esta politica exacta (ver comentario completo en `.env.example`):
`ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `s3:ListAllMyBuckets`,
`s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`, `s3:GetPublicAccessBlock`,
`s3:GetBucketLocation` -- y despues conectar esa cuenta desde la pagina
"Integraciones Cloud" (las credenciales se configuran ahi, nunca por variable
de entorno). Como siempre, correr `docker compose build && docker compose up`
para levantar el servicio nuevo (no se puede correr Docker desde este
entorno).

Verificacion antes de commitear: 30 tests nuevos en cloud-service (funciones
puras, sin boto3/red/DB real) + 41 tests de vitest (sin cambios, no se tocaron
utils) + `tsc --noEmit` limpio + `npm run build` exitoso en el frontend
completo.

## Nueva funcionalidad: Escaneo de código y repositorios (2026-09-26)

Tercera de las 8 funcionalidades pedidas por Manu, priorizada como #3
(superficie externa/threat intel y cloud AWS ya hechas). Detecta contraseñas
o claves subidas por error a un repositorio de código y dependencias
vulnerables en el codigo, tal como se pidio.

**`coderepo-service` (puerto 8015)**: el usuario registra un repositorio
(URL HTTPS + rama + token opcional para repos privados). Un scheduler
periodico (cada `CODEREPO_SCAN_INTERVAL_HOURS` horas, default 24) y un boton
"Escanear ahora" clonan el repositorio COMPLETO (con todo el historial de
git, no solo el checkout actual -- un secreto commiteado por error y borrado
despues sigue expuesto en el historial) y corren dos herramientas
especializadas:

- **gitleaks**: revisa todo el historial de git buscando contraseñas, claves
  privadas, tokens de AWS/GCP/Azure/GitHub, etc. Los hallazgos se guardan en
  `coderepo-service` con severidad (`critical`/`high`/`medium` segun el tipo
  de regla) -- el valor real del secreto NUNCA se guarda ni se muestra, solo
  una version parcialmente oculta (ej `AKI••••••••••••WXYZ`).
- **trivy fs**: revisa manifiestos de dependencias (package-lock.json,
  requirements.txt, go.mod, etc.) contra la base de CVEs conocidas -- misma
  herramienta que ya usa scan-service para imagenes de contenedor, pero con
  su propia cache de DB separada (`coderepo_trivy_cache`, nunca comparte
  volumen con scan-service). Estos hallazgos se reenvian directamente a
  vuln-service (aparecen mezclados en la seccion Vulnerabilidades ya
  existente, no se duplican en una tabla nueva).

Es de solo lectura/analisis en todo momento: nunca se escribe nada en el
repositorio del cliente ni se ejecuta codigo del repositorio (nunca se corre
`npm install`, un build, un test, ni se importa nada de lo clonado). El
token de GitHub de un repo privado se cifra con el mismo mecanismo ya usado
para SSO/AWS (`backend/shared/crypto.py`) y nunca se devuelve por la API.

Nueva pagina de frontend "Código y Repositorios" (nav, junto a
"Integraciones Cloud"): alta de repositorio, tabla de repositorios con
estado del ultimo escaneo y contadores de secretos/vulnerabilidades
encontradas (con link directo a Vulnerabilidades), tabla de secretos
encontrados con filtro pendiente/todos y boton "Reconocer".

**Paso manual pendiente para Manu**: ninguno especial mas alla de
`docker compose build && docker compose up` -- gitleaks/trivy/git se
instalan solos en la imagen del servicio nuevo. Para repos privados, generar
un token de acceso personal de solo lectura (GitHub: "read-only, contents")
y pegarlo al conectar el repositorio desde la pagina.

Verificacion antes de commitear: 46 tests nuevos en coderepo-service
(funciones puras, sin git/gitleaks/trivy/red/DB real) + 41 tests de vitest
(sin cambios) + `tsc --noEmit` limpio + `npm run build` exitoso en el
frontend completo.

## Resultados de escaneos legibles: criticidad y remediacion a la vista (2026-09-27)

Manu pidio que los resultados de los escaneos se vean "de forma completa",
"facilmente legible", con criticidad asignada y medidas de remediacion. Al
revisar el codigo, `vuln-service` ya calculaba todo eso desde hace tiempo
(severidad, CVSS, EPSS, si esta en CISA KEV, un `priority_score` combinado,
y hasta pasos de remediacion sugeridos por regla en
`app/remediation.py`) -- la brecha real era que el frontend no lo mostraba
donde el usuario lo esperaba. No se duplico logica de remediacion en el
cliente: se reuso `vuln-service` como fuente unica de verdad.

- **`vuln-service`**: se agrego un filtro opcional `scan_job_id` a
  `GET /vulnerabilities` (`app/main.py` + `app/services.py`) para poder
  pedir "los hallazgos de ESTE escaneo puntual" sin tocar el modelo de
  datos. Ojo (documentado como comentario en el codigo): si el mismo activo
  se volvio a escanear despues, `ingest_findings` reasigna el
  `scan_job_id` de una vulnerabilidad al escaneo MAS RECIENTE que la toco
  -- este filtro muestra el estado actual de esas vulnerabilidades, no
  necesariamente los hallazgos crudos de un escaneo viejo si hubo un
  rescan.
- **Pagina "Escaneos"**: cada escaneo (tanto en "Escaneos realizados" como
  en "Escaneos remotos") tiene ahora un boton "Ver resultados" que despliega,
  sin salir de la pagina, cada hallazgo con su badge de severidad, CVE,
  paquete/version instalada -> version corregida (si aplica), puerto/servicio
  (si aplica), descripcion, y la lista de pasos de remediacion sugeridos. Si
  el escaneo fallo se muestra el motivo del error en vez de una tabla vacia;
  si todavia esta en curso, se avisa que los resultados van a aparecer solos
  cuando termine.
- **Pagina "Vulnerabilidades"**: se agregaron filtros por severidad y por
  estado (los resuelve el backend, via los mismos parametros que ya
  soportaba `GET /vulnerabilities`) mas una busqueda de texto libre por
  titulo/CVE/paquete (del lado del cliente, sobre el resultado ya filtrado).
  El detalle expandido de cada fila ahora tambien muestra la descripcion
  completa y tarjetas de paquete/puerto/origen antes de los pasos de
  remediacion (que ya existian). Se agregaron tarjetas de resumen para
  Criticas y Altas en la parte superior.

Verificacion antes de commitear: los 20 tests existentes de vuln-service
siguen en verde (pytest), import-sanity de `app.main` confirmando que las
rutas quedan bien registradas, `tsc --noEmit` limpio y `npm run build`
exitoso en el frontend completo.

**Paso manual pendiente para Manu**: solo hace falta reconstruir
`vuln-service` y `frontend` (no todo el stack) --
`docker compose build vuln-service frontend` y despues
`docker compose up -d vuln-service frontend`.

## Cancelar escaneos en curso + aviso de aislamiento de red LAN en Docker (2026-09-27)

Manu reporto que sus escaneos nmap de LAN (ej. 192.168.x.x) siempre terminan
en el timeout de 180s, y pidio poder cancelar un escaneo que quedo
"running". Dos cosas separadas, ambas resueltas:

- **Cancelar un escaneo pending/running**: nuevo endpoint
  `POST /scans/{id}/cancel` en `scan-service`. Cada corrida de
  `execute_scan_job` se auto-registra (via `asyncio.current_task()`) en un
  registro en memoria (`_RUNNING_SCAN_TASKS`, un solo dict de proceso --
  mismo supuesto que ya usa el scheduler de `ScanSchedule`) mientras corre;
  cancelar le pide `Task.cancel()` a esa tarea, y cada driver
  (nmap/trivy/nuclei/openvas) atrapa el `CancelledError` resultante para
  matar el subproceso en curso (nmap/trivy/nuclei) antes de re-lanzarlo --
  sin esto, el binario seguia corriendo huerfano dentro del contenedor
  aunque el job ya quedara marcado como cancelado, igual que ya pasaba con
  el timeout. El driver de OpenVAS es un caso especial: el escaneo real lo
  corre gvmd/ospd-openvas del otro lado del socket, no un subproceso local
  nuestro, asi que ademas se le manda un `stop_task` GMP best-effort al
  task remoto para no dejarlo corriendo huerfano ahi tambien. Si no hay
  ninguna tarea viva registrada para ese job (por ejemplo, quedo "running"
  huerfano de un reinicio del contenedor), se marca cancelado directamente
  en la DB -- no hay nada que matar. Nuevo estado `cancelled` en
  `ScanStatus`, cuenta como estado terminal (se puede borrar despues, igual
  que completed/failed/scanner_unavailable). En el frontend, cada fila de
  "Escaneos realizados" en estado pending/running ahora tiene un boton
  "Cancelar".
- **Aviso de aislamiento de red antes de escanear, no despues de esperar
  180s**: el timeout de nmap contra un rango LAN/oficina no es un bug --
  Docker Desktop aisla al contenedor de `scan-service` detras de NAT, y no
  hay forma confiable de darle acceso real a la LAN de la PC desde ahi
  (`network_mode: host` en Docker Desktop para Windows/Mac no expone la
  LAN real del host como en Linux nativo). La solucion real a esto ya
  existia en el producto -- el agente de "Escaneos remotos" corre FUERA de
  Docker y si llega a la LAN -- pero el usuario solo se entraba de la
  limitacion despues de esperar el timeout completo. Se agrego un aviso
  visible en el formulario "Nuevo escaneo" en cuanto se elige ambito LAN o
  MAN, explicando el aislamiento de Docker y señalando directamente a
  "Escaneos remotos" como la forma correcta de escanear la red real.

Verificacion antes de commitear: 68 tests en scan-service (62 existentes +
6 nuevos de la logica de cancelacion, sin DB ni drivers reales) todos en
verde, import-sanity de `app.main` confirmando que `POST /scans/{id}/cancel`
queda bien registrado, `tsc --noEmit` limpio y `npm run build` exitoso en
el frontend completo.

**Paso manual pendiente para Manu**: solo hace falta reconstruir
`scan-service` y `frontend` -- `docker compose build scan-service frontend`
y despues `docker compose up -d scan-service frontend`. Nota: cancelar un
escaneo de agente remoto ("Escaneos remotos") todavia no esta soportado --
esos corren en `remote-agent/agent.py`, un proceso aparte que hace polling,
y cancelarlos requeriria cambiar ese protocolo. Quedo fuera de esta corrida.

## Subida de imagenes a trivy, agente remoto multi-scanner, OpenVAS opcional, dashboard de imagenes/paquetes (2026-09-28)

Habia un cambio grande (935 lineas, 9 archivos) sin commitear en el repo,
generado antes de esta corrida, que ya implementaba bastante de lo que
Manu pidio a continuacion: subir una imagen/manifiesto para escanearlo con
trivy, un agente remoto que corre los 4 scanners, y OpenVAS/GVM detras de
un profile opcional (esto ultimo, ademas, resuelve el crash de
`scap-data`/`data-objects` que se venia arrastrando por falta de espacio
en Docker Desktop). Se reviso ese cambio (74 tests en verde -- 68 previos +
6 nuevos para `is_running_status` y `agent_key_matches`, import-sanity de
`app.main`, YAML valido con las dependencias del profile "openvas"
consistentes, tsc + build limpios) y se commiteo aparte
(`fd88d15`), excluyendo expresamente "sentinel para sofi" (un export propio
de Manu para un cliente, sin relacion con el desarrollo).

A partir de ahi, dos pedidos puntuales de Manu:

- **nuclei en el agente remoto quedaba "assigned" sin completar**:
  `run_nuclei` en `remote-agent/agent.py` no tenia el flag `-duc` que si
  tiene el driver in-container -- sin el, nuclei chequea/baja templates
  nuevas en CADA escaneo, lo que puede tardar varios minutos segun la
  conexion de la maquina del agente (el loop del agente nunca crashea, ya
  atrapa cualquier excepcion, asi que no era un cuelgue sino la demora real
  del chequeo). Se agrego `-duc` y un refresco propio en background (una
  vez al arrancar y despues cada 12hs, igual que `refresh_nuclei_templates`
  en scan-service) para que las templates no queden desactualizadas para
  siempre. README actualizado: la seccion "Requisitos" solo mencionaba nmap
  y quedo vieja cuando se agrego soporte multi-scanner.

- **Dashboard de imagenes y paquetes escaneados con trivy**: trivy normal
  solo reporta paquetes CON un CVE conocido (`Results[].Vulnerabilities`).
  Se agrego el flag `--list-all-pkgs` (en el driver in-container y en el
  path de archivos subidos) para que el JSON traiga ademas
  `Results[].Packages`, el inventario COMPLETO independientemente de si
  tiene CVE o no. Nueva columna `ScanJob.packages` (JSON, con su
  `ALTER TABLE ADD COLUMN IF NOT EXISTS` para instalaciones existentes,
  igual que se hizo con `organization_id`), nuevo endpoint
  `GET /scan-images` que agrupa por imagen/target y se queda con el
  escaneo mas reciente de cada una (reescanear actualiza en vez de
  duplicar), y pagina nueva en el frontend ("Imagenes y Paquetes", nueva
  entrada de navegacion) con el listado de imagenes + paquetes expandibles
  por imagen y filtro de busqueda. La logica de agrupacion se separo en
  una funcion pura (`services.build_image_inventory`) para poder testearla
  sin DB, como el resto de las reglas de negocio de este servicio.
  **Fuera de alcance**: los escaneos trivy lanzados via "Escaneos remotos"
  (agente) no alimentan este dashboard todavia -- solo los escaneos
  normales y los subidos por archivo.

Verificacion antes de commitear: 87 tests en scan-service (74 anteriores +
13 nuevos: `_parse_trivy_packages` y el flag `--list-all-pkgs` en
`test_trivy_driver.py`, `build_image_inventory` en
`test_image_inventory.py`), import-sanity de `app.main` confirmando
`GET /scan-images`, tsc --noEmit limpio y `npm run build` exitoso en el
frontend completo. `remote-agent/agent.py` no tiene suite de pytest (su
verificacion establecida es `test_pipeline.py` con el stack real
levantado) -- se verifico con `py_compile` + revision manual.

**Paso manual pendiente para Manu**: esta vez el cambio es grande y toca
`docker-compose.yml` (perfiles + servicio `remote-agent` nuevo) y el
schema de la DB (columna `packages`) ademas del codigo de
`scan-service`/`frontend` -- conviene reconstruir TODO el stack, no solo
dos servicios:

```powershell
docker compose build
docker compose up -d
```

Con esto, GVM/OpenVAS **no** arranca (esta detras del profile `openvas`,
ver `openvas/LEEME.md` en la raiz para prenderlo cuando haga falta un
assessment profundo autenticado). El `ALTER TABLE ... ADD COLUMN` corre
solo al arrancar `scan-service`, asi que la columna `packages` se crea
sola en la base existente sin perder datos. Los dos agentes remotos
("Agente Docker" y "Agente LAN") se auto-registran solos -- el Agente LAN
necesita ademas correr `remote-agent/agente-lan.ps1` en la PC que va a ver
la LAN real (ver `remote-agent/README.md`).

## Agente Docker: falla rapido contra LAN + jobs en paralelo (2026-09-28)

Con logs reales que Manu paso (nmap y nuclei quedaban en PENDING/asignados
sin terminar), se diagnostico que el problema no era el stack sin
reconstruir sino dos bugs de fondo en `remote-agent/agent.py` (el "Agente
Docker" que corre dentro de Docker Desktop):

- `run_once` corria los jobs de una misma tanda en un for secuencial: un
  nuclei lento (o colgado) contra una IP de LAN bloqueaba a un nmap ya
  asignado que hubiera terminado en segundos. Se paso a
  `ThreadPoolExecutor` (`AGENT_MAX_CONCURRENT_JOBS=8` por defecto) para que
  cada job asignado en la misma tanda corra en su propio thread y reporte
  su resultado apenas termina, sin esperar a los demas. De paso, una
  excepcion no manejada en un runner ya no deja el job "assigned" para
  siempre -- ahora se atrapa y se reporta como "failed".
- trivy/nuclei/openvas no tienen forma de atravesar el NAT de Docker
  Desktop hacia la LAN real (a diferencia de nmap, que ya usa un escaner
  TCP interno propio para eso) -- contra una IP privada (192.168.x.x,
  10.x.x.x, etc.) se quedaban varios minutos intentando conectar antes de
  fallar por timeout, lo que se veia como "colgado". Con
  `AGENT_BEHIND_DOCKER_NAT=1` (seteado solo para el servicio `remote-agent`
  en `docker-compose.yml` -- el Agente LAN, que corre fuera de Docker, no
  lleva esta variable porque el no tiene el problema) esos 3 scanners
  ahora fallan al toque contra un target de LAN, con un mensaje que apunta
  a usar el Agente LAN en su lugar.

Verificacion: `py_compile` limpio y un script ad-hoc (remote-agent no
tiene suite de pytest, ver su README -- su verificacion establecida es
`test_pipeline.py` contra el stack real) que stubea `SCANNERS` y
`submit_result` sin red real: confirma que el guard bloquea
trivy/nuclei contra IP de LAN solo con `AGENT_BEHIND_DOCKER_NAT=1`, que
nmap nunca se bloquea, y que 5 jobs de 0.3s corridos via el executor
tardan ~0.3s en total en vez de ~1.5s (paralelismo real). Suite de
scan-service sin cambios, sigue 87/87 verde.

**Paso manual pendiente para Manu**: este cambio toca solo
`remote-agent/agent.py` y la variable `AGENT_BEHIND_DOCKER_NAT` en
`docker-compose.yml` -- alcanza con reconstruir ese servicio:

```powershell
docker compose build --no-cache remote-agent
docker compose up -d
```

## Api key de los agentes bootstrap visible en la UI + proteccion contra borrado (2026-09-28)

Manu reporto el motivo de fondo por el que no podia lanzar escaneos
remotos: "Agente Docker" y "Agente LAN" se crean solos al arrancar
`scan-service` (via `BOOTSTRAP_AGENTS` en `.env`, ver
`services.ensure_bootstrap_agent`), pero como se crean directo en la base
-- no via `POST /agents`, el unico endpoint que devuelve la api key en
claro, y solo una vez -- esa key nunca aparecia en ningun lado de la UI.
Sin poder verla ahi, la unica forma de usarla era ir a copiarla a mano
desde el `.env` del servidor. Ademas, al ser agentes como cualquier otro
en la tabla, se podian borrar por error desde "Eliminar", lo que rompe los
escaneos remotos hasta el proximo restart de `scan-service` (que los
vuelve a crear).

Como la key en si nunca se guarda en claro en la base (solo
`ScanAgent.key_hash`, un hash SHA-256 -- ver `_hash_agent_key`), mostrarla
en la UI para estos dos agentes puntuales significa re-derivarla: se
agrego `resolve_bootstrap_api_key()` en `services.py`, que parsea de
nuevo el JSON de `BOOTSTRAP_AGENTS` (el mismo que ya tiene Manu en su
`.env`, asi que no es una exposicion nueva) y devuelve la key en claro
cuya hash coincide con la del agente. `is_protected_agent()` marca a un
agente como protegido si `created_by == "bootstrap"` (el mismo criterio
que ya usaba `ensure_bootstrap_agent`).

- `GET /agents` ahora devuelve, ademas de los campos de siempre,
  `is_protected` y `bootstrap_api_key` (`null` para agentes creados a
  mano, que siguen sin exponer su key en ningun lado salvo al momento de
  crearlos, como siempre).
- `DELETE /agents/{agent_id}` devuelve 409 con un mensaje explicando el
  porque si el agente es protegido, en vez de borrarlo.
- En el frontend (`Scans.tsx`): la tabla de "Agentes de escaneo remoto"
  ahora tiene una columna "Api key" (con la key en claro para los dos
  bootstrap, copiable) y, en la columna de accion, un agente protegido
  muestra "Protegido" (con tooltip explicando el porque) en vez del boton
  "Eliminar". Ademas, al elegir uno de estos dos agentes en el selector de
  "Escaneos remotos", el campo de api key del formulario se autocompleta
  solo -- Manu ya no necesita copiar/pegar la key desde ningun lado para
  lanzar un escaneo remoto.

Verificacion: 7 tests nuevos (`test_bootstrap_agent_protection.py`,
`is_protected_agent` y `resolve_bootstrap_api_key` con objetos fake, sin
DB real) sobre la suite existente -- 94/94 en verde. Import-sanity de
`app.main` (26 rutas, sin errores). `tsc --noEmit` y `npm run build`
limpios en el frontend completo.

**Paso manual pendiente para Manu**: este cambio toca solo
`scan-service` y `frontend` -- no `remote-agent` ni `docker-compose.yml`
ni el schema de la base:

```powershell
docker compose build --no-cache scan-service frontend
docker compose up -d
```

Con el stack arriba, refrescar el navegador (Ctrl+Shift+R) para que
tome el frontend nuevo. La api key de "Agente Docker" y "Agente LAN" va a
aparecer directo en la tabla de agentes de `/scans`, y ya no se van a
poder borrar desde ahi.

## Agente LAN no se llevaba sus propios jobs: carrera contra Agente Docker (2026-09-28)

Manu reporto, con capturas: un job de nuclei mandado explicitamente a
"Agente LAN" contra `192.168.0.1` terminaba FAILED, pero con el mensaje de
error que tira el guard de LAN-detras-de-NAT (ver seccion anterior) -- un
mensaje que dice "este agente (Agente Docker)... usa el Agente LAN para
este target". O sea: el job estaba dirigido a Agente LAN, pero lo proceso
Agente Docker.

La causa: `poll_agent_jobs` en `services.py` le da a los agentes bootstrap
("Agente Docker" y "Agente LAN", los dos siempre-encendidos) trato de
"worker universal" -- pueden tomar cualquier job pendiente, sin importar a
que agente lo mandaron, para cubrirse entre si si uno esta caido. El
problema es que esto corria SIN ningun margen: un job recien creado para
Agente LAN era candidato para Agente Docker desde el instante cero, asi
que quedaba una carrera pura entre los dos poll loops (gana el que
pollee primero). Si Agente LAN nunca llego a arrancar (`agente-lan.ps1`
no estaba corriendo -- la tabla de agentes lo mostraba como "nunca hizo
polling", que es justo lo que se vio en las capturas) o si Agente Docker
sencillamente pollea primero, Agente Docker se lleva el job -- y como
tiene el guard de LAN activado (`AGENT_BEHIND_DOCKER_NAT=1`), lo rechaza
al toque en vez de dejarselo a un Agente LAN que si podria haberlo
resuelto.

Se agrego `agent_can_claim_job()`, una funcion pura que decide si un
agente puede llevarse un job candidato: el agente al que se lo mandaron
siempre puede tomarlo apenas esta "pending" (sin cambios ahi); un agente
bootstrap distinto solo puede tomarlo como red de contencion despues de
`UNIVERSAL_WORKER_GRACE_SECONDS` (60s, mayor al intervalo de polling por
defecto del agente) sin que el agente elegido lo haya tomado el mismo; y
la recuperacion de jobs "assigned" huerfanos hace mas de 10 min sigue
igual que antes. `poll_agent_jobs` ahora trae los candidatos de la base
(mismo query de siempre) y filtra con esta funcion en vez de decidir todo
en el WHERE, justamente para poder testear la regla sin DB real, como el
resto de las reglas de negocio de este servicio.

Con esto, si Agente LAN esta prendido y polleando (su intervalo por
defecto es de 10s), se lleva sus propios jobs muchisimo antes de que se
cumplan los 60s de margen, y Agente Docker nunca llega a competir por
ellos. Si Agente LAN nunca aparece, Agente Docker lo sigue tomando igual
tras el margen -- sigue habiendo una red de contencion, pero ya no le
gana la carrera a un Agente LAN que si esta activo.

Verificacion: 12 tests nuevos (`test_agent_job_claiming.py`) cubriendo
las 4 combinaciones (propio/ajeno x bootstrap/no-bootstrap) en pending,
el limite exacto del margen de 60s, la recuperacion de assigned huerfanos
y sus bordes (sin created_at/assigned_at, otros estados) -- suite
completa de scan-service en 106/106 verde. Import-sanity de `app.main`
(26 rutas, sin errores).

**Paso manual pendiente para Manu**: este cambio toca solo
`scan-service` (nada de `remote-agent` ni `docker-compose.yml` ni el
schema de la base):

```powershell
docker compose build --no-cache scan-service
docker compose up -d
```

Esto no reemplaza tener que arrancar `remote-agent/agente-lan.ps1` en una
PC con visibilidad real a la LAN -- si ese script no esta corriendo, un
job mandado a "Agente LAN" sigue sin tener quien lo resuelva de verdad
(Agente Docker lo va a tomar igual a los 60s como red de contencion, pero
va a fallar con el mismo mensaje de siempre, porque el no puede atravesar
el NAT). Vale la pena confirmar que la tabla de agentes en `/scans`
muestre a "Agente LAN" con una fecha reciente en "Ultima vez visto" antes
de lanzar un escaneo de LAN.

## Agente LAN: instalacion en un solo paso + aviso claro de sus limites (2026-09-28)

Manu: "quiero que remote-agent/agente-lan.ps1 se cree al darle lanzar
escaneo remoto asi trabaja automaticamente y no tengo que estar
creandolo yo ni el cliente, ante todo tiene que ser facil de usar".

Antes de tocar nada se investigo si era posible que scan-service (corre
DENTRO de Docker) arranque el proceso solo al lanzar un escaneo -- no lo
es: Docker esta aislado del host por diseno (es justo el motivo de que
exista un Agente LAN aparte), asi que ningun backend puede lanzar un
proceso en la PC del cliente por su cuenta. Se le pregunto a Manu como
prefiere resolver el primer arranque en una maquina nueva, y eligio
instalarlo como tarea de Windows que arranca sola.

De paso, revisando `agente-lan.ps1` a fondo salio a la luz la causa real
de fondo del "nuclei no anda con el Agente LAN" de la seccion anterior:
el script PowerShell nativo de este agente (hecho asi para NO requerir
instalar nada -- ni Python ni nmap) **solo implementa descubrimiento de
puertos al estilo nmap** -- nunca soporto nuclei/trivy/openvas, ni antes
ni ahora. El fix de la carrera entre agentes (turno anterior) resuelve
que el job llegue al agente correcto, pero un nuclei contra un target de
LAN sigue sin tener quien lo resuelva: ni el Agente Docker (bloqueado
por el NAT) ni el Agente LAN (nunca tuvo nuclei). El README afirmaba lo
contrario (que el Agente LAN era "la solucion real" para esos 3
scanners) -- estaba desactualizado/incorrecto, se corrigio.

Cambios:

- `agente-lan.ps1` gana `-Install` / `-Uninstall` / `-Status`: `-Install`
  se registra como tarea de Windows (modulo `ScheduledTasks`, ya viene
  con Windows 10/11 -- no instala nada nuevo) que arranca sola en cada
  inicio de sesion, sin pedir ser administrador, y la arranca ya mismo
  de paso (no hay que cerrar sesion y volver a entrar). Corre oculto
  (`-WindowStyle Hidden`, sin ventana) y ahora loguea a
  `remote-agent/agente-lan.log` ademas de la consola (agrega
  `Write-Log`), para poder diagnosticar sin dejarlo en primer plano.
  `-Status` muestra si esta instalado, la ultima corrida y las ultimas
  lineas del log; `-Uninstall` lo saca de los programas de inicio.
- Nuevo `Instalar-Agente-LAN.bat`: doble-clic UNA VEZ y queda instalado
  -- pensado para Manu y, mas adelante, para un cliente sin conocimientos
  tecnicos. `Iniciar-Agente-LAN.bat` (ya existia) se mantiene para correrlo
  a mano en una ventana visible (probarlo una vez, ver en vivo).
- El mensaje que devuelve un job de nuclei/trivy/openvas contra el
  Agente LAN ya no manda al usuario en circulos ("usa el Agente
  Docker" -- que tambien lo va a rechazar si es un target de LAN):
  ahora explica que este agente todavia no soporta ese scanner y cuando
  tiene sentido probar el Agente Docker (solo si el target es
  alcanzable desde internet/host, no LAN).
- `Scans.tsx`: si "Agente LAN" nunca hizo polling o hace mas de 5
  minutos que no aparece, la tabla de agentes muestra un aviso con la
  instruccion exacta (doble-clic en `Instalar-Agente-LAN.bat`) en vez de
  dejar que el usuario se entere recien cuando un escaneo de LAN se
  quede pending.
- `README.md`: se reemplazo el `schtasks` manual (con la ruta del repo
  de Manu hardcodeada) por instrucciones de `Instalar-Agente-LAN.bat`,
  se corrigio "requiere nmap instalado" (el script no lo requiere, hace
  su propio TCP scan nativo) y se aclaro en la seccion de troubleshooting
  que el Agente LAN no reemplaza a trivy/nuclei/openvas contra la LAN.

Verificacion: revision manual linea por linea del PowerShell (sin
interprete de PowerShell disponible en este entorno para correrlo --
mismo criterio que ya se uso para `agent.py` cuando no hay forma de
ejecutarlo real, ver secciones anteriores), balance de llaves/parentesis
chequeado por script. `tsc --noEmit` y `npm run build` limpios en el
frontend completo. Suite de scan-service sin cambios de backend en esta
seccion, sigue 106/106 verde.

**Fuera de alcance, a decidir con Manu**: nuclei/trivy/openvas contra
targets de LAN siguen sin tener quien los resuelva (ver arriba) -- la
unica forma hoy es correr `remote-agent/agent.py` (el agente Python
completo) directo en una PC con esos binarios instalados, lo cual ya no
es "cero instalacion". Si Manu quiere esto resuelto de forma mas
automatica (ej. que `agente-lan.ps1` use nuclei.exe/trivy.exe si estan
instalados, con nmap nativo como fallback), es un cambio de alcance
mayor -- no se decidio unilateralmente en este turno, queda pendiente de
confirmar.

**Paso manual pendiente para Manu**: instalar el Agente LAN una vez en
cada PC que vaya a ver una red real (la tuya y, mas adelante, la de cada
cliente) -- doble-clic en `remote-agent/Instalar-Agente-LAN.bat`. No
hace falta reconstruir ni reiniciar el stack de Docker para esto (no se
toco `scan-service` en esta seccion), pero conviene reconstruir el
frontend para ver el aviso nuevo en la tabla de agentes:

```powershell
docker compose build --no-cache frontend
docker compose up -d
```

## Agente LAN: soporte real de nuclei/trivy (no solo puertos) (2026-09-28)

Manu probo un nuclei contra el Agente LAN y volvio a fallar (con el
mensaje honesto agregado en la seccion anterior: "todavia solo hace
descubrimiento de puertos... no tiene nuclei instalado"). Le pregunte
directamente como prefiere resolverlo -- instalar los binarios reales en
la PC del Agente LAN, o dejarlo como esta (solo puertos, nuclei/trivy
solo para targets de internet via Agente Docker) -- y eligio la primera.

`agente-lan.ps1` ahora detecta `nuclei.exe`/`trivy.exe` con
`Get-Command` en CADA job (no solo al arrancar, para que instalarlos
mientras el agente ya esta corriendo funcione sin reiniciarlo) y, si
estan en el PATH, los corre de verdad contra el target -- mismos flags
que el driver in-container y `agent.py` (nuclei: `-etags
dos,fuzz,intrusive -jsonl -silent -no-interactsh -duc`, sin exploit ni
scripts intrusivos; trivy: `image`/`fs --format json`), y el mismo
parseo de resultados (severidad, cve_id, paquete/version para trivy;
severidad, cve_id, matched-at para nuclei) para que las respuestas se
vean iguales sin importar que agente las corrio. Si no estan instalados,
el job vuelve con un mensaje que dice exactamente que instalar y un link
-- y el PROXIMO job de ese scanner ya funciona solo, sin reiniciar nada.
openvas sigue sin soporte aca (necesita el motor completo de Greenbone,
no un binario suelto invocable como nuclei/trivy).

Correr un binario externo con limite de tiempo real (y poder matarlo si
se cuelga) no es trivial en PowerShell puro -- se agrego
`Invoke-ScannerBinary`, que usa `System.Diagnostics.Process`
directamente (en vez de `Start-Process`, que no da control fino de
timeout+kill) para lograr el equivalente de `subprocess.run(...,
timeout=N)` de Python.

De paso se corrigio un bug latente en `Submit-Result`: armaba el JSON a
mano con concatenacion de strings (`"...""raw_output"":""$raw""..."`),
lo cual se rompia apenas `$raw` o el mensaje de error trajeran una
comilla -- exactamente lo que trae SIEMPRE un JSON real de nuclei/trivy.
No se habia notado antes porque el unico raw_output que mandaba este
agente era un string fijo sin comillas ("agente LAN (PowerShell)"). Se
reemplazo por construir el payload entero como objeto y serializarlo una
sola vez con `ConvertTo-Json`, que escapa todo correctamente.

Verificacion: revision manual linea por linea del PowerShell (sin
interprete disponible en este entorno, mismo criterio que las secciones
anteriores de agente-lan.ps1), balance de llaves/parentesis/corchetes
chequeado por script. README actualizado (ya no dice que el Agente LAN
"no reemplaza" a nuclei/trivy -- ahora aclara que si puede, si estan
instalados). Suite de scan-service sin cambios de backend, sigue
106/106 verde.

**Paso manual pendiente para Manu**: instalar `nuclei` y/o `trivy` en la
PC donde corre el Agente LAN (deben quedar en el PATH -- probalo
abriendo una consola nueva y corriendo `nuclei -version` / `trivy
--version`). No hace falta reiniciar `Iniciar-Agente-LAN.bat` ni la
tarea instalada: el agente los detecta solos en el proximo job. No hay
que reconstruir nada de Docker para esto (no se toco `scan-service` ni
`docker-compose.yml`).

## nuclei/trivy instalados directamente en la carpeta del Agente LAN (2026-09-28)

Manu: "quiero que vos instales nuclei y trivy directamente en mi
carpeta de programa asi arrancan automaticamente" -- despues de que la
seccion anterior dejara la deteccion de binarios lista pero todavia
dependiente de que el sistema los tuviera instalados el mismo.

No hay forma de instalar un .exe de Windows "de verdad" (con su entrada
en el PATH, etc.) desde este entorno -- pero si se puede descargar el
binario oficial y dejarlo en una carpeta que el script ya sabe buscar,
sin que haga falta ninguna instalacion real ni tocar variables de
entorno de Windows. Eso es lo que se hizo:

- Se descargaron los binarios oficiales de la ultima release de cada
  proyecto (`nuclei_3.11.1_windows_amd64.zip` de
  github.com/projectdiscovery/nuclei, `trivy_0.74.0_windows-64bit.zip`
  de github.com/aquasecurity/trivy), **se verifico el sha256 de cada
  zip contra el checksums.txt que publica cada proyecto en su propia
  release** (coincidieron los dos) antes de extraer nada, y se copiaron
  `nuclei.exe`/`trivy.exe` a `remote-agent/bin/` (nueva carpeta, al lado
  del script).
- `agente-lan.ps1` gano `Resolve-ScannerBinary($name)`: busca primero en
  el PATH del sistema (por si el operador lo instalo "normal") y, si no
  esta ahi, en `remote-agent/bin/$name.exe`. Reemplazo los 6 lugares que
  antes hacian `Get-Command nuclei/trivy` a mano. Ya no hace falta que
  nuclei/trivy esten en el PATH de Windows para que el Agente LAN los
  use -- alcanza con que el .exe este en esa carpeta.
- `remote-agent/bin/` **no se commitea** -- `*.exe` ya estaba en
  `.gitignore` desde antes, y por buena razon: nuclei.exe (145MB) y
  trivy.exe (172MB) superan largamente el limite de 100MB por archivo
  de GitHub, y aunque no lo superaran, no tiene sentido versionar
  binarios de terceros de ese tamano en el historial de git para
  siempre. Quedan en el disco de la maquina (que es lo que hace que el
  agente los encuentre), simplemente no viajan con el repo -- en otra
  maquina (o la de un cliente) hay que repetir la descarga ahi.

README actualizado para reflejar que el Agente LAN busca en dos
lugares (PATH y `remote-agent/bin/`), no solo el PATH.

Verificacion: sha256 de los dos zips contra los checksums oficiales
(coincidieron exacto), revision manual del PowerShell (sin interprete
disponible en este entorno), balance de llaves/parentesis/corchetes por
script, confirmacion de que `git status` no muestra los .exe nuevos
(gitignore funcionando). Suite de scan-service sin cambios de backend,
sigue 106/106 verde.

**Nada pendiente para Manu de este lado** -- los binarios ya estan en
`remote-agent/bin/` en su maquina. Si corre `Iniciar-Agente-LAN.bat` (o
ya tiene el Agente LAN instalado como tarea, ver seccion anterior) el
banner de arranque va a loguear "nuclei: disponible (...)" / "trivy:
disponible (...)", y los proximos jobs de esos scanners contra targets
de LAN deberian completar en vez de fallar.


## Dashboard de administracion avanzada de OpenVAS (2026-10-03)

El backend de scan-service ya tenia, desde una corrida anterior, el modulo
completo `app/gvm_manage.py` con 18 endpoints `/openvas/*` para administrar
credenciales de escaneo autenticado, targets reutilizables, tasks y
exportacion de reportes contra gvmd real (con tenancy por organizacion ya
corregida en la auditoria de seguridad transversal) -- pero ningun lugar
del frontend los consumia. Scans.tsx solo cubre activacion/estado y
lanzar un escaneo puntual, nunca administracion de esos recursos
reutilizables.

- Pagina nueva `frontend/src/pages/OpenvasDashboard.tsx` (ruta `/openvas`,
  nav "OpenVAS avanzado"): 3 paneles -- credenciales (alta por formulario
  + tabla + borrado), targets (alta con hosts + lista de puertos +
  credenciales SSH/SMB opcionales, poblados desde `/openvas/port-lists` y
  `/openvas/credentials` + tabla + borrado) y analisis/reportes (tabla con
  estado, barra de progreso real via `refetchInterval`, y exportacion
  PDF/CSV/XML por fila usando el mismo patron blob-download que
  Reports.tsx). Si OpenVAS todavia no esta activado, la pagina lo detecta
  (`GET /openvas/status`) y redirige con un link a Escaneos en vez de
  mostrar tablas vacias o errores 409 confusos.
- Auto-apertura: Scans.tsx ahora ofrece un link a `/openvas` apenas
  termina una activacion exitosa (ademas de uno persistente en el panel
  normal una vez que OpenVAS ya esta listo), para que el usuario encuentre
  la administracion avanzada sin tener que buscarla sola por el menu.
- `Badge.tsx`: se agrego el estado nativo de gvmd "done" (equivalente a
  "completed") a `STATUS_CLASS` -- los demas estados de task de gvmd sin
  mapeo especifico (New/Requested/Queued/Stop Requested) caen al badge
  neutral por defecto, que ya es correcto.
- `/help`: tema nuevo "OpenVAS avanzado" con la misma guia en espanol
  simple que el resto de las secciones.

No hizo falta tocar nada de backend (los 18 endpoints y los tipos
TypeScript ya existian). Verificacion: `npx tsc --noEmit` limpio,
`npm run test -- --run` (41/41 verde, sin agregar tests nuevos --
OpenvasDashboard.tsx es composicion de UI sobre endpoints ya testeados
del lado del backend, sin logica pura nueva que valga la pena extraer) y
`npm run build` limpio.

**Nada pendiente para Manu de este lado.**

## Aviso previo de "LAN detras del NAT de Docker" en Escaneos remotos (2026-10-02)

Manu reporto un escaneo OpenVAS fallido via el agente "gvm" (Agente
Docker) contra `192.168.0.143`, con un error en la fila del job. Reves
el codigo (`remote-agent/agent.py::_process_job` + `_is_private_ip_target`,
flag `AGENT_BEHIND_DOCKER_NAT`): esto es un guardrail YA EXISTENTE y
correcto, no un bug -- el "Agente Docker" corre dentro de Docker Desktop
y queda detras de su NAT, entonces nuclei/trivy/openvas no pueden llegar
a una IP de LAN real (nmap si puede, tiene fallback propio). El agente
ya detecta esto ANTES de intentar el escaneo (para no perder minutos en
un timeout) y falla rapido con un mensaje que dice exactamente que
hacer: usar el Agente LAN (`remote-agent/agente-lan.ps1`, corriendo en
una PC con visibilidad real a esa red) para targets de LAN con estos
scanners.

Lo que SI faltaba: la UI de "Escaneos remotos" (Scans.tsx) dejaba elegir
esa combinacion (Agente Docker + scanner distinto de nmap + target de
LAN) sin avisar nada hasta despues de crear el job y esperar el poll del
agente para recien ahi leer el error. Se agrego un aviso previo, no
bloqueante, en el mismo formulario: si el agente elegido tiene "docker"
en el nombre (mismo criterio ya usado para la etiqueta de "Escaneos
programados"), el scanner no es nmap, y el target matchea una IP
RFC1918/loopback/link-local (`isLikelyPrivateIpTarget`, espejo en
TypeScript de `_is_private_ip_target` del agente), se muestra un parrafo
de advertencia con el mismo texto que el agente va a devolver, antes de
que Manu tenga que lanzar el escaneo y esperar para enterarse. No se
bloquea el boton (un hostname interno igual se deja pasar, por ejemplo)
-- es solo para ahorrar la vuelta.

Verificacion: `npx tsc --noEmit` limpio, `npm run test -- --run` (41/41
verde, sin tests nuevos -- es una funcion pura chica, el valor de
testearla aislada es bajo comparado con el resto de la suite) y
`npm run build` limpio.

**Para Manu: el error que viste es esperado -- "Agente Docker" nunca va
a poder escanear tu LAN real con nmap/nuclei/openvas salvo nmap. Para
`192.168.0.143` con openvas, corre `remote-agent/Instalar-Agente-LAN.bat`
+ `Iniciar-Agente-LAN.bat` en una PC con visibilidad real a esa red (puede
ser la misma PC donde corre SentinelOps) y elegi ese agente ("Agente
LAN") en el selector en vez de "Agente Docker" (el que probablemente
elegiste, llamado "gvm" o similar en tu lista de agentes). Si "Agente
LAN" no aparece en el selector, es que agente-lan.ps1 no esta corriendo
en ninguna PC todavia.**

## render.yaml para licensing-server + investigacion de "archivos que no se pueden subir al repo" (2026-10-02)

Manu pregunto (via consejo de una amiga) tres cosas: 1) el problema que
tiene con archivos que no puede subir al repo, 2) si su programa anda
igual en Render que en local, 3) si es asi, un `render.yaml` para
desplegar rapido.

**Investigacion del punto 1** (`remote-agent/bin/`): encontre
`trivy.exe` (172MB) y `nuclei.exe` (145MB), ambos arriba del limite
duro de 100MB por archivo de GitHub. Ya estan correctamente excluidos
por la regla `*.exe` de `.gitignore` -- `git ls-files` confirma que
NINGUN `.exe` esta trackeado hoy, asi que un `git push` ahora mismo no
deberia rechazar nada por esto. Si el problema que vive Manu es otro
(otro archivo, otro error), falta que lo describa para investigar ese
caso puntual -- esto es la hipotesis mas probable dado lo que hay en
el repo, no una confirmacion.

**Punto 2 (licensing-server especificamente, no el resto de
SentinelOps)**: revise `app/db.py`, `Dockerfile` y `.env.example` --
ya esta escrito a proposito para andar igual en los dos caminos desde
el principio (toggle SQLite/Postgres por `DATABASE_URL`, puerto
leido de `$PORT`, sin threads/websockets/cron en proceso, health
check en `/health`). Respuesta: SI, anda igual en Render que en local
-- las unicas diferencias son de plataforma (el plan free duerme sin
trafico, agrega latencia en el primer request), no de codigo. El
resto de SentinelOps (scan-service, openvas, etc.) NO esta pensado
para Render -- se distribuye como RAR on-prem a proposito (requiere
Docker socket, capabilities de red privilegiadas, visibilidad de LAN
real -- nada de eso existe en una plataforma como Render), asi que el
Blueprint cubre solo licensing-server.

**Punto 3**: `render.yaml` nuevo en la raiz del repo, 1 servicio
(`sentinelops-licensing-server`, `runtime: docker`, apuntando a
`licensing-server/Dockerfile` con ese mismo directorio como build
context), `healthCheckPath: /health`, `plan: free`, variables de
entorno declaradas con `sync: false` (las pide Render al crear el
servicio, nunca quedan en el repo) salvo `ADMIN_TOKEN`
(`generateValue: true`, Render lo genera solo) y los valores no
sensibles que ya tenian default en `.env.example` (URLs de retorno de
PayPal/Mercado Pago, `PAYPAL_ENV=sandbox`). Verifique la sintaxis
parseando el YAML con `python3 -c "import yaml; yaml.safe_load(...)"`
y confirme contra la documentacion oficial de Render (`runtime: docker`
reemplaza al campo viejo `env: docker`; `autoDeployTrigger` reemplaza
a `autoDeploy`). `licensing-server/README.md` ahora menciona este
atajo de Blueprint en la seccion "Desplegar en Render + Neon", con una
nota de que Render cambio de planes en julio 2026 y no pude confirmar
si el nivel free sigue sin pedir tarjeta -- Manu deberia confirmarlo
el mismo en el paso de signup.

**Para Manu**:
- Si el problema de archivos no era el de trivy.exe/nuclei.exe,
  describime que error te tira exactamente al subir (que archivo, que
  mensaje) para investigar el caso real.
- `render.yaml` listo para usar: Render dashboard -> New -> Blueprint
  -> elegir este repo. Te va a pedir `DATABASE_URL` (connection string
  de Neon) y `LICENSE_SIGNING_PRIVATE_KEY` (la que genera
  `generate_keys.py`) en el momento de crear el servicio.

## Se sacaron nmap, Nessus Essentials y OpenVAS del producto: queda trivy + nuclei (2026-10-03)

Manu pidio sacar nmap y Nessus Essentials enteros del programa ("no son
aptos para vender"), revirtiendo ademas una migracion OpenVAS -> Nessus que
estaba en curso en esta misma sesion. Confirmo explicitamente que el alcance
final de escaneres queda en **trivy + nuclei unicamente** -- sin ningun
scanner de puertos/red ni de vulnerabilidades de infraestructura.

Se audito y limpio el repo completo, sin dejar nada roto ni mencionado:

- **Backend (`scan-service`)**: se borraron `app/scanners/nmap.py`,
  `app/scanners/nessus.py` y `app/nessus_manage.py`. `app/scanners/nuclei.py`
  perdio su preflight interno que shelleaba a `nmap -sn`. `app/models.py` y
  `app/schemas.py` quedaron con `ScannerType`/`scanner_type` limitados a
  `trivy`/`nuclei` (se borro todo el modelo/schemas de `NessusCredentials`).
  `app/services.py` perdio toda la logica de credenciales/tenancy de Nessus.
  `app/main.py` perdio el bloque entero de endpoints `/nessus/*` -- de paso
  se encontro y arreglo un bug preexistente (el decorador `@app.post("/scans"
  ...)` faltaba sobre `create_scan`, dejando esa ruta inalcanzable). El
  Dockerfile ya no instala `nmap`. Tests: se borraron
  `test_nmap_driver.py`/`test_nessus_driver.py`, se reescribio
  `test_target_ssrf_validation.py` sin mencionar nmap/nessus, y se
  actualizaron referencias incidentales en otros tests. 102/102 tests en
  verde.
- **`remote-agent/`**: `agent.py` (829 -> 397 lineas) perdio el escaner TCP
  interno, `run_nmap`, y todo el cliente REST de Nessus (`run_nessus` y sus
  helpers). `agente-lan.ps1` perdio `Expand-Hosts`/`Scan-HostPorts` (su
  escaner de puertos nativo) y el branch `scanner -eq "nmap"`, mas el
  mensaje de fallback que mandaba a usar Nessus. `test_pipeline.py` y
  `README.md` quedaron documentando solo trivy/nuclei (README tambien
  perdio toda la tabla de variables `NESSUS_*`).
- **`docker-compose.yml`**: se sacó `AGENT_FORCE_INTERNAL_NMAP` del servicio
  `remote-agent` (agent.py ya no lo lee) y se reescribieron sus comentarios
  (ya no mencionan nmap/Nessus).
- **`.env`/`.env.example`**: se sacaron `GVM_*`, `REMOTE_AGENT_GVM_KEY` y la
  entrada `"gvm"` de `BOOTSTRAP_AGENTS` -- resabios de la limpieza de
  OpenVAS/GVM anterior a esta sesion que habian quedado sin sacar (el agente
  bootstrap "gvm" se hubiera seguido auto-registrando en cada arranque de
  scan-service sin que nada lo pudiera usar).
- **Frontend**: se borro `NessusDashboard.tsx` y la ruta `/nessus` (`App.tsx`,
  `Layout.tsx`). En `Scans.tsx` se sacaron el tipo `ScannerType` de 4 valores
  (ahora solo `trivy`/`nuclei`), el modo nmap rapido/completo, el query de
  `nessus/status` y toda la UI condicional de Nessus en los 3 paneles
  ("Nuevo escaneo" ahora es nuclei-only contra WAN; "Escaneos programados" y
  "Escaneos remotos" ofrecen trivy/nuclei); el aviso de aislamiento de red
  por NAT de Docker ahora aplica por igual a los 2 scanners (antes nmap y
  nessus quedaban exceptuados). De paso se encontro y arreglo una referencia
  a una variable `openvasReady` que no existia en ningun lado (bug latente
  de una limpieza de OpenVAS anterior que quedo a medio hacer) y un import
  de `useEffect` sin usar. `Assets.tsx` (boton de escaneo rapido por activo)
  y `Badge.tsx`/`RunningIndicator.tsx`/`theme.css` (comentarios y badges de
  estados de Nessus) tambien quedaron limpios. `npx tsc --noEmit`, 41 tests
  (`vitest run`) y `npm run build` -- los 3 en verde.
- **Docs y varios**: se saco la seccion entera "Stack OpenVAS/GVM" de
  `docs/architecture.md` (describia infraestructura que ya no existe en
  `docker-compose.yml` desde antes de esta sesion) y las menciones a
  nmap/OpenVAS en `docs/runbook.md`, `docs/security.md` (incluida la fila
  STRIDE de `ospd-openvas`, un contenedor que tampoco existe mas),
  `README.md`, `render.yaml`, el `Makefile` (target `test-openvas`, que
  apuntaba a un servicio `openvas-orchestrator` inexistente en el compose) y
  un par de strings de muestra en `siem-service`/`vuln-service`.

**Resultado para Manu**: el producto queda enfocado en dos escaneres:
**trivy** (CVEs en imagenes de contenedor/paquetes, via subida de archivo o
en escaneos programados) y **nuclei** (deteccion por plantillas sobre
hosts/URLs, sin las categorias `dos`/`fuzz`/`intrusive` -- solo deteccion,
nunca explotacion). No queda ningun scanner de puertos/descubrimiento de red
(lo que hacia nmap) ni ningun motor de vulnerabilidades de infraestructura
tipo Nessus/OpenVAS. Esto es una reduccion real de alcance respecto de donde
arranco el producto (OpenVAS) -- antes de llevarlo a mercado asi, vale la
pena confirmar que trivy + nuclei cubre lo que tus clientes esperan, o si
hace falta sumar otra capacidad de escaneo de red/infraestructura que sí
este lista para vender.

## Se suman 6 scanners con licencias aptas para vender: ZAP, Semgrep, Gitleaks, YARA, Zeek, Falco (2026-10-03)

Manu pidio implementar, en Escaneos programados y Escaneos remotos, los
scanners que una investigacion de licenciamiento previa habia identificado
como legalmente aptos para vender el software sin restricciones (ver el
analisis en el doc de licencias ya compartido). Se le pregunto
explicitamente por Zeek/Falco -- son herramientas de monitoreo continuo, no
"escanea un target y termina" como trivy/nuclei -- y elegio sumar las 6
igual, forzando Zeek/Falco como jobs de **duracion fija** (ventana
configurable 1-60 min, default 5).

El producto pasa de 2 a **8 scanners**: `trivy`, `nuclei` (ya existian) +
`zap` (OWASP ZAP, Apache-2.0), `semgrep` (motor LGPL-2.1, **reglas propias
unicamente** -- nunca el registro publico `auto`/`p/...`, que tiene una
licencia que prohibe ofrecerlo como parte de un servicio a terceros),
`gitleaks` (MIT), `yara` (BSD-3-Clause, **reglas propias unicamente**, por
la misma razon que semgrep pero con packs de terceros), `zeek`
(BSD-3-Clause) y `falco` (Apache-2.0). Quedaron deliberadamente afuera
ClamAV, Opengrep, Suricata, Wazuh/OSSEC, Grafana Loki/Tempo y TruffleHog
(cada uno con un problema de licencia o de alcance distinto, ver el doc de
licencias).

- **Backend (`scan-service`)**: 6 drivers nuevos en `app/scanners/`
  (`zap.py`, `semgrep.py`, `gitleaks.py`, `yara.py`, `zeek.py`, `falco.py`),
  mismo patron que `trivy.py`/`nuclei.py` (subprocess async, timeout,
  `ScanResult`). Dos piezas compartidas nuevas: `_codetarget.py` (resuelve
  un target a un `git clone` temporal si es una URL http(s), o a un path
  local existente -- la usan semgrep y gitleaks) y `_duration.py`
  (`resolve_duration_seconds`, acota `options.duration_minutes` a 1-60,
  default 5 -- la usan zeek y falco: en zeek el timeout de
  `asyncio.wait_for` ES el fin exitoso de la captura, no un error; falco
  usa su propio flag nativo `-M <segundos>`). `app/models.py` suma los 6
  valores a `ScannerType`. `app/schemas.py` extiende el denylist SSRF: zap/
  semgrep/gitleaks pueden tener un target de red y se siguen chequeando;
  yara/zeek/falco nunca reciben un host/URL como target y quedan exentos
  (igual que trivy ya lo estaba). `requirements.txt` suma `semgrep==1.86.0`
  (motor LGPL-2.1 invocado como binario externo via subprocess, nunca
  importado como libreria). Reglas propias nuevas en
  `rules/semgrep/sentinelops-rules.yml` (12 reglas) y
  `rules/yara/sentinelops.yar` (5 reglas, incluye deteccion de EICAR,
  webshells PHP obfuscados, PE embebido en archivo no-ejecutable,
  PowerShell obfuscado y one-liners de reverse shell en Python). El
  `Dockerfile` instala los 6 binarios nuevos (gitleaks/ZAP via tarball de
  GitHub releases, Zeek via el repo OBS de openSUSE, Falco via su repo apt
  oficial -- estos 2 ultimos con fallback no-fatal si el build corre en una
  arquitectura/distro donde el repo no esta disponible) y copia las 2
  carpetas de reglas dentro de la imagen. `docker-compose.yml` suma los
  capabilities de Linux que Zeek (`NET_RAW`/`NET_ADMIN`) y Falco
  (`SYS_ADMIN`/`SYS_RESOURCE`/`SYS_PTRACE`/`BPF`/`PERFMON`, driver eBPF
  moderno) necesitan a `scan-service` y `remote-agent`. 166/166 tests en
  verde (`test_zap_driver.py`, `test_semgrep_driver.py`,
  `test_gitleaks_driver.py`, `test_yara_driver.py`, `test_zeek_driver.py`,
  `test_falco_driver.py`, `test_codetarget.py` nuevos; `test_target_ssrf_
  validation.py` ampliado con los 6 scanners nuevos).
- **`remote-agent/`**: `agent.py` suma `run_zap`/`run_semgrep`/
  `run_gitleaks`/`run_yara`/`run_zeek`/`run_falco` (mismo patron sync que
  ya tenia para trivy/nuclei) y generaliza `_is_private_ip_target` para
  parsear URLs completas (necesario para zap). `agente-lan.ps1` (PowerShell
  nativo, sin Python) suma las 4 que SI puede correr en Windows nativo --
  `zap`/`semgrep`/`gitleaks`/`yara`, con su propio `Resolve-CodeTarget` -- y
  rechaza `zeek`/`falco` con un mensaje claro de "usa el Agente Docker"
  (necesitan captura de paquetes/eBPF de Linux, que Windows nativo no
  tiene). `test_pipeline.py` y `README.md` quedaron documentando los 8
  scanners.
- **Frontend (`Scans.tsx`)**: `ScannerType` pasa de 2 a 8 valores. Los 2
  selects de scanner (Escaneos programados y Escaneos remotos) ofrecen los
  8. Cuando se elige `zeek`/`falco` en cualquiera de los 2 formularios
  aparece un input "Duracion (min)" (1-60, default 5) que se manda como
  `options.duration_minutes`. El aviso de "LAN detras del NAT de Docker" se
  generalizo para reconocer tambien un target tipo URL (no solo IP/CIDR
  pelada), asi tambien avisa para `zap` (y de paso para semgrep/gitleaks si
  el repo a clonar esta en un git server interno).
- **`.env.example`**: se documentaron (comentadas, no requeridas --
  tienen default sensato) las 3 variables que permiten apuntar
  `agente-lan.ps1`/`agent.py` a un set de reglas/home distinto al que
  viene con el repo: `SENTINELOPS_SEMGREP_RULES_DIR`,
  `SENTINELOPS_YARA_RULES_FILE`, `SENTINELOPS_ZAP_HOME_DIR`.
- **`THIRD-PARTY-LICENSES.md`** (nuevo, en la raiz): atribucion de
  copyright y licencia de cada uno de los 8 motores de escaneo que usa el
  producto.

**Resultado para Manu**: el producto pasa de 2 a 8 scanners, todos con
licencias que permiten venderlo sin pedirle permiso a nadie (Apache-2.0,
MIT, BSD-3-Clause, o LGPL-2.1 usado correctamente como binario externo).
**Dos cosas pendientes de tu lado, no resueltas en esta sesion**: (1) el
`Dockerfile` quedo reescrito pero **nunca se corrio `docker compose build`**
-- instalar Zeek/Falco via sus repos apt puede fallar segun la
arquitectura/version de Docker Desktop (WSL2 vs Hyper-V), conviene buildear
y revisar los logs antes de confiar en que los 8 binarios quedaron
instalados; (2) `agente-lan.ps1` no se pudo correr por ningun interprete de
PowerShell real durante esta sesion (solo revision manual linea por linea)
-- probalo a mano con un job de cada uno de los 4 scanners nuevos que
soporta (zap/semgrep/gitleaks/yara) antes de darlo por funcionando en
produccion.

### Verificacion post-deploy en la maquina de Manu (2026-10-03)

El build real de `docker compose build scan-service remote-agent` fallo en
el primer intento por un conflicto de dependencias de pip (`pydantic==2.9.2`
fijado antes de sumar semgrep es incompatible con `semgrep==1.86.0`, que
pide `pydantic~=2.8.2`) -- corregido bajando el pin a `2.8.2` (commit
`caa84da`, ver seccion de arriba). Despues de ese fix, build y
`docker compose up -d` completos. `scan-service` quedo "unhealthy" en el
primerisimo arranque (primera vez que los volumenes `trivy_cache`/
`nuclei_templates` existian, Docker tuvo que copiarles el contenido
horneado en la imagen -- mas lento que el `start-period` del
`HEALTHCHECK`, que no tiene gracia explicita) pero quedo sano al
reintentar `docker compose up -d` una segunda vez, sin cambiar nada mas.

Confirmado dentro del contenedor (`docker compose exec scan-service sh -c
"which trivy nuclei zap.sh semgrep gitleaks yara zeek falco"`): los 8
binarios estan instalados y responden. `zeek --version` -> 9.0.0.
`falco --version` corrio limpio sobre el kernel WSL2 de Docker Desktop de
Manu (`6.18.33.2-microsoft-standard-WSL2`) -- soporta lo que el driver
eBPF "moderno" de falco necesita, asi que la preocupacion de licenciamiento
original sobre si WSL2 iba a alcanzar quedo resuelta: alcanza.

**Pendiente real, ahora si acotado**: falta lanzar un job de cada scanner
nuevo desde la UI (Escaneos programados y Escaneos remotos) contra un
target de prueba real, para confirmar que cada driver -- no solo el
binario -- anda de punta a punta (parseo de resultados, severidades,
reenvio a vuln-service). Los binarios ya estan confirmados; falta probar
los 6 flujos completos.

### Los 6 scanners nuevos, confirmados de punta a punta (2026-10-03)

Se encontraron y arreglaron 3 bugs reales corriendo los binarios de
verdad (no mocks) contra la maquina de Manu -- ninguno lo habia
agarrado la suite de tests automatizada porque sus mocks reproducian
la misma suposicion incorrecta que el codigo real:

- **yara**: el parseo de `yara -s` asumia la linea de detalle de cada
  cadena matcheada indentada con tab/espacio; en la version real no
  viene indentada (`0xOFFSET:$id: contenido`), asi que esa linea se
  colaba como un hallazgo falso. Arreglado en los 3 lugares que repiten
  este parseo (`app/scanners/yara.py`, `agent.py`, `agente-lan.ps1`).
- **falco**: `--json-output` no existe como flag en la version real
  (0.45.0) -- Falco lo saca a favor de `-o json_output=true`. Arreglado
  en `app/scanners/falco.py` y `agent.py`.
- **zeek**: fallaba con `pcap_activate: Operation not permitted` pese al
  `cap_add` del contenedor -- esas capabilities no las hereda un
  proceso no-root a menos que el BINARIO las tenga marcadas. Arreglado
  con `setcap cap_net_raw,cap_net_admin+eip` sobre el binario de zeek
  durante el build.
- **semgrep**: devolvia 0 findings en TODOS los escaneos sin reportar
  error -- `sentinelops-rules.yml` tenia 2 patterns con un `:` sin
  comillas que rompian el parser de YAML, tumbando el archivo ENTERO
  (sus 12 reglas), no solo esas 2. Arreglado entre comillas.

gitleaks y zap funcionaron bien de entrada, sin bugs.

Confirmado el ciclo completo (gitleaks, semgrep, yara, zap, zeek, falco)
corriendo cada driver de verdad -- no mocks -- contra targets reales
chicos, directamente dentro del contenedor `scan-service` (sin pasar por
la UI/login): los 4 primeros detectaron exactamente el hallazgo
esperado; zeek y falco corrieron limpios sus 60 segundos sin ningun
error de permisos/driver (0 hallazgos ahi es el resultado correcto para
una ventana sin actividad sospechosa real que capturar).

De paso se encontraron y se le avisaron a Manu 2 problemas de
infraestructura sin relacion con este trabajo: Docker Desktop tuvo un
hiccup transitorio del engine (resuelto con un reinicio normal) y habia
7 contenedores huerfanos de la vieja stack OpenVAS/GVM (uno en loop de
reinicio) que quedaron de una limpieza anterior sin terminar -- se le
indico `docker compose up -d --remove-orphans` para sacarlos.

**Pendiente real, ahora si de verdad acotado**: falta lanzar al menos un
escaneo de cada uno de los 6 desde la UI (Escaneos programados y
Escaneos remotos), no solo invocando el driver directo -- para confirmar
el camino completo API -> DB -> reenvio a vuln-service. Y falta copiar
los binarios de zap/semgrep/gitleaks/yara a `remote-agent/bin/` (o al
PATH) de la PC donde corre el Agente LAN, si se lo quiere usar para
estos 4 scanners ahi tambien (hoy solo el Agente Docker los tiene).

### Cierre de los pendientes del cierre anterior (2026-10-03)

- Confirmado que el push de `bc3efda` llego bien a `origin/main`.
- Manu confirmo que ya corrio `docker compose up -d --remove-orphans` --
  los 7 contenedores huerfanos de OpenVAS/GVM quedaron limpios.
- Se bajo `gitleaks.exe` (binario oficial de la release de GitHub,
  `v8.30.1`, MIT) a `remote-agent/bin/gitleaks.exe` -- el Agente LAN ya
  lo puede usar sin instalar nada en esa PC, igual que ya pasaba con
  `nuclei.exe`/`trivy.exe`.
- **yara NO se pudo bundlear igual**: el proyecto no publica un
  `yara.exe` precompilado en sus releases de GitHub (solo codigo
  fuente) -- documentado en el README (seccion de Requisitos) con las
  alternativas (compilar a mano, o `choco install yara`/vcpkg) para
  cuando se quiera usar yara desde el Agente LAN. zap y semgrep tampoco
  se pueden bundlear como un solo `.exe` (zap necesita un JRE instalado
  completo, semgrep es un paquete de Python) -- hay que instalarlos de
  verdad en esa PC si se los quiere usar ahi.
- La prueba end-to-end desde la UI real (Escaneos programados/remotos,
  no solo el driver directo) la va a hacer Manu el mismo lanzando un
  escaneo de cada uno; queda fuera del alcance de Claude por no manejar
  su sesion/credenciales de usuario.

Con esto, de los 3 pendientes que quedaban abiertos al cierre anterior,
2 estan resueltos (orphans, binario de gitleaks) y 1 queda
explicitamente a cargo de Manu (prueba UI-level) por la restriccion de
credenciales -- no porque falte algo del lado del codigo.

## Agente WAN (internet) + limpieza de restos de OpenVAS/GVM/nmap (2026-10-05)

Pedido de Manu: sacar "del todo" los rastros de OpenVAS (agente GVM) y nmap,
y sumar a "Agentes de escaneo remoto" un agente WAN (internet).

- **Restos en la base**: el codigo de OpenVAS/GVM/nmap/Nessus ya estaba
  borrado, pero en la base quedaba (a) el agente bootstrap "gvm" -- siempre
  "Protegido" en la UI porque `ensure_bootstrap_agent` solo crea, nunca
  borra -- y (b) posibles escaneos/reglas con scanner_type nmap/openvas/
  nessus, que `ScanJob` ya no puede ni cargar. `scan-service` ahora, al
  arrancar y ANTES de registrar las reglas programadas: borra esas filas
  (`purge_legacy_scanner_rows`) y borra los agentes bootstrap que ya no
  figuran en `BOOTSTRAP_AGENTS` junto con sus escaneos remotos y reglas
  (`prune_stale_bootstrap_agents`; un `BOOTSTRAP_AGENTS` vacio o roto nunca
  borra nada). Los agentes creados a mano no se tocan. Tests:
  `tests/test_stale_bootstrap_agents.py`.
- **Agente WAN (internet)**: tercer agente bootstrap, servicio
  `remote-agent-wan` en `docker-compose.yml` (misma imagen, sin capabilities
  elevadas, `AGENT_ROLE=wan`). `remote-agent/agent.py::_wan_rejection`
  rechaza objetivos privados/internos (IPs RFC1918, loopback, link-local,
  `localhost`, `host.docker.internal`, `*.local`/`.internal`/`.lan`...) y los
  scanners zeek/falco/yara. Key nueva `REMOTE_AGENT_WAN_KEY` + entrada en
  `BOOTSTRAP_AGENTS` (`.env` y `.env.example`). La UI (`Scans.tsx`) avisa
  antes de lanzar si se elige el Agente WAN con una IP privada o con un
  scanner no soportado. Tests: `remote-agent/test_wan_agent.py`.
- Se quito de `scan-service/Dockerfile` el comentario que seguia mencionando
  gvm-cli.
