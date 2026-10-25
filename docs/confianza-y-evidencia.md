# Confianza y evidencia

Pantalla **Confianza y evidencia** (menu lateral). Reune lo que TERO puede *demostrarle* a un auditor,
a un cliente o a un juez, de forma que ellos lo puedan verificar **sin tener que confiar en nosotros**.

Cada funcion explica abajo que prueba y que **no** prueba. Ninguna reemplaza una opinion legal o una
auditoria formal.

## 1. Cadena de custodia digital

**Para que sirve.** Poder demostrar que lo que paso en un caso (alertas, acciones de respuesta, cambios
de estado, escaneos, cierres de vulnerabilidades) quedo registrado en su momento y no se modifico ni se
borro despues.

**Como funciona.**

- Cada evento relevante se anota en una cadena por organizacion. Cada entrada guarda la huella
  (SHA-256) de la anterior: borrar o reordenar algo rompe todo lo que sigue.
- Cada entrada se firma con **Ed25519**. La clave publica se puede entregar a cualquiera; la privada
  nunca sale del servidor.
- Los eventos llegan solos desde `siem-service` (alertas), `soar-service` (playbooks), `vuln-service`
  (estados), `scan-service` (escaneos) y `case-service` (casos). Si `case-service` no responde, el
  servicio que emite reintenta desde una cola en memoria (hasta 500 eventos; se pierde si ese servicio se
  reinicia antes de lograr entregarlos).
- Solo `case-service` puede escribir eventos `case.*` y `evidence.*`.

**Como se usa.**

1. *Confianza y evidencia → Cadena de custodia → Verificar la cadena ahora*: recorre la cadena completa
   y avisa en que entrada se rompe, si se rompe.
2. *Paquete de evidencia de un caso* (o el boton **Descargar evidencia** en *Casos*): baja un `.zip` con
   la ficha del caso, todos sus eventos firmados, el listado completo de huellas de la cadena, un
   `LEEME.txt` y `verificar_evidencia.py`. De los eventos de otros casos solo hay huellas, no datos.
3. El auditor corre, en cualquier computadora con Python 3 y **sin acceso a TERO**:

   ```
   python verificar_evidencia.py evidencia-caso.zip
   python verificar_evidencia.py evidencia-caso.zip --huella 9f3a-01bc-...   # huella de la clave que le diste en mano
   ```

   El verificador usa solo la biblioteca estandar de Python e incluye su propia verificacion Ed25519.
   Hace 5 controles: cadena y firmas, eventos mostrados = eventos firmados, ficha del caso = la
   exportacion registrada, ancla firmada y coherente, y (opcional) huella de la clave.
4. *Ancla externa*: genera un registro firmado (cantidad + huella final) para guardar **fuera** de TERO
   (mail, ticket, carpeta aparte). Despues se puede verificar la cadena contra esa ancla.

**Configuracion recomendada.** Definir `CUSTODY_SIGNING_SEED` en `.env` (texto largo y secreto) antes
de empezar a usar la cadena. Si no esta definido, la clave se deriva de `JWT_SECRET_KEY` (funciona, pero
queda atada a ese secreto). Cambiar la semilla mas adelante invalida las firmas ya hechas.

**Limites (decirlos en voz alta).**

- Prueba **integridad y momento**: que el sistema registro eso y cuando. No prueba que los hechos sean
  verdaderos.
- Quien tenga la semilla de firma o administre el servidor podria rehacer una cadena completa. Por eso
  existen el ancla externa y la huella de la clave entregada por otro canal.
- Si `case-service` estuvo caido y se reinicio el servicio emisor, pueden faltar eventos de ese lapso
  (no se manipulan: simplemente no llegaron).
- La validez legal de un paquete depende de la jurisdiccion y del perito que lo presente.

## 2. Prueba de soberania

**Para que sirve.** Responder con evidencia a "¿TERO manda datos a algun lado que yo no sepa?". Pestana
**Soberania** (solo `admin` y `soc_manager`).

**Como funciona.**

- **Auditor de salidas.** Todos los servicios de TERO anotan con que destinos *externos* hablan: solo el
  nombre del sitio (nunca la ruta, los parametros ni el contenido) y cuantas veces. Lo interno (nombres de
  servicio de Docker, `localhost`, IP privadas, `.local`, `.lan`, `.corp`) no cuenta como salida. Cada
  minuto cada servicio informa a `case-service`.
- **Catalogo.** Cada destino se clasifica: *Conocido* (esta en el catalogo: a quien, para que y que datos
  viajan), *Configurado por un administrador* (un webhook, el SMTP, un SSO, un repositorio o una cuenta de
  nube que cargo una persona) o *No catalogado* (un destino externo que nadie pudo haber configurado: es lo
  primero que hay que mirar). Si sumas una integracion que sale a internet, agregala a
  `backend/services/case-service/app/egress_catalog.py`.
- **Modo aislado.** Con `docker-compose.aislado.yml`, toda salida externa se frena **antes de salir**
  (HTTP, SMTP, AWS, `git clone`, validacion de Google) y queda anotada como bloqueada. Ademas la red de TERO
  se crea sin traduccion de direcciones (`enable_ip_masquerade=false`), asi que lo que intente salir no tiene
  como volver.
- **Prueba de red.** El boton *Probar salida a internet ahora* intenta conectarse de verdad a tres destinos de
  prueba (`1.1.1.1:443`, `8.8.8.8:53`, `9.9.9.9:443`; cambialos con `TERO_PROBE_TARGETS`) y resuelve un nombre
  DNS (solo informativo). No envia ningun dato. Queda anotada en la cadena de custodia.
- **Veredicto.** *Aislado y verificado* solo si los 15 servicios informan modo aislado **y** la prueba de red
  no pudo salir. Si la aplicacion bloquea pero la red no esta confirmada, dice *Aislado por la aplicacion,
  falta confirmar la red*. Si hay salidas no catalogadas, el veredicto es *Hay salidas no catalogadas*.
- **Atestado firmado.** *Descargar atestado firmado* baja un JSON firmado (Ed25519, la misma clave de la
  cadena de custodia) con el veredicto, los servicios, los destinos y la ultima prueba. Se verifica sin TERO:

  ```
  python verificar_evidencia.py atestado-soberania.json
  ```

**Activar el modo aislado.**

```
docker compose down
docker compose -f docker-compose.yml -f docker-compose.aislado.yml up -d
```

Volver al modo normal: `docker compose -f docker-compose.yml -f docker-compose.aislado.yml down` y despues
`docker compose up -d`. Para dejar pasar un destino puntual (ej. el SMTP de la empresa) agregalo a
`TERO_EGRESS_ALLOW` en `.env` (hosts separados por coma; incluye sus subdominios).

**Que deja de funcionar en modo aislado (a proposito).** Consultas a NVD, EPSS, CISA KEV, crt.sh y AbuseIPDB;
clonado desde GitHub; correo por un SMTP externo; SSO con Google o Microsoft; avisos a Slack/Teams/Jira en la
nube. Lo local (escaneos de tu red, SIEM, SOAR, casos, reportes) sigue igual. `trivy` y `nuclei` necesitan su
cache ya descargada (volumenes `trivy_cache` y `nuclei_templates`).

**Limites (decirlos en voz alta).**

- Solo se ve lo que sale por la aplicacion (HTTP, SMTP, AWS, git). Un programa externo que un servicio
  lance como proceso (`trivy`, `nuclei`) no se mide desde adentro: por eso manda la prueba de red.
- `scan-service` conserva una red normal ("escaneo") para poder llegar a los equipos de tu red local; ahi rige
  solo el modo aislado de la aplicacion. TERO lo informa asi en la pantalla y en el atestado
  (`TERO_NETWORK_EXCEPTIONS`).
- La prueba de red se hace desde el contenedor de `case-service`. Si otros servicios estan en otras redes,
  probalos aparte.
- El aislamiento de red del compose depende de Docker: las opciones de una red no se cambian en caliente (por eso
  el `down` previo) y no se pudo verificar contra un Docker real durante el desarrollo; **la prueba de red es el
  juez**, no el archivo de configuracion. `remote-agent` queda fuera: corre del lado de tus objetivos.
- El atestado prueba lo que TERO observo hasta firmarlo, no lo que ocurra despues. Un servicio que no
  informa figura como "sin informes recientes" y el veredicto no pasa de *Con salidas controladas*.
- Si `case-service` esta caido, los servicios guardan los contadores y los informan al volver (si el
  servicio se reinicia antes, esos contadores se pierden).

## 3. Cierre verificado de vulnerabilidades

**Que resuelve.** En casi todas las herramientas, "remediada" es un clic de una persona. Si alguien se equivoca (o se apura), la vulnerabilidad figura como cerrada y sigue ahi. TERO no se queda con la declaracion: **repite el mismo escaneo que la encontro y solo la da por cerrada si ya no aparece.**

**Como funciona.**

1. Alguien pasa la vulnerabilidad a *remediada* (en Vulnerabilidades o desde la API).
2. `vuln-service` pide a `scan-service` repetir el escaneo original (mismo escaner, objetivo y opciones). Queda anotado en la cadena como `vuln.closure_requested`.
3. Cuando el re-escaneo termina:
   - **Ya no la detecta** → `verificado`. Se anota `vuln.closure_verified` con el tiempo de cierre real.
   - **La vuelve a detectar** → `cierre fallido`: la vulnerabilidad se **reabre sola** (`open`, con la nota "Reabierta: el re-escaneo de verificacion la volvio a detectar") y se anota `vuln.closure_failed`.
   - **El re-escaneo fallo, se borro o no termino en 6 horas** → `sin concluir`. Nunca se da por verificada sin un escaneo completo. Se puede reintentar con "Verificar ahora".
   - **No se puede repetir** (archivo subido, agente remoto, nube, superficie de ataque, codigo, falco/zeek/yara) → `no verificable`, con el motivo a la vista.
4. En **Confianza y evidencia → Cierre verificado** se ve el tiempo de cierre **declarado** (hasta que alguien dijo "listo") contra el **real** (hasta la verificacion), la tasa de cierres falsos y el detalle por severidad.

**Prueba firmada.** Cada cierre verificado o fallido se puede bajar con "Descargar prueba" (`GET /closure/{id}/attestation` en case-service): es un atestado `tero-attestation` de tipo `closure`, firmado con la clave de la cadena de custodia. Se comprueba sin TERO:

```
python verificar_evidencia.py prueba-cierre.json
```

**Variables (.env).**

| Variable | Por defecto | Para que |
|---|---|---|
| `VULN_AUTO_VERIFY_CLOSURE` | `true` | `false` = no se pide el re-escaneo solo; queda "sin verificar" y se pide a mano |
| `VULN_CLOSURE_POLL_SECONDS` | `30` | cada cuanto se revisan los re-escaneos pendientes |
| `VULN_CLOSURE_TIMEOUT_HOURS` | `6` | tras cuanto sin terminar pasa a "sin concluir" |

**Limites honestos.**

- "Verificado" quiere decir que *el escaneo repetido ya no la detecta*, no que sea imposible explotarla. Si el objetivo estaba apagado y el escaner termino sin informar un error, podria dar un falso verificado; por eso el detalle muestra cuantos hallazgos tuvo el re-escaneo.
- Si la vulnerabilidad vuelve a aparecer mas tarde despues de un cierre verificado, se registra como una vulnerabilidad nueva (el cierre anterior sigue siendo cierto para ese momento).
- Los hallazgos que vienen de un archivo subido o de un agente remoto no se pueden repetir automaticamente.

## 4. Cumplimiento con evidencia viva

**Que resuelve.** Preparar una auditoria, una renovacion de seguro o una consulta legal suele ser juntar capturas y completar planillas a mano. TERO ordena los controles que se le piden a una organizacion argentina que trata datos personales y los **comprueba con datos reales**; lo que no puede ver lo declara una persona, con nombre, nota, fecha y vencimiento.

**Normativa que se cita (verificada).**

- **Ley 25.326** de Proteccion de los Datos Personales: art. 9 (seguridad de los datos, la obligacion legal de fondo), art. 10 (confidencialidad), art. 12 (transferencia internacional), arts. 14 a 16 (acceso, rectificacion, actualizacion y supresion) y art. 21 (inscripcion de las bases).
- **Resolucion AAIP 47/2018**: aprueba medidas de seguridad **recomendadas** (referenciales, no obligatorias). Derogo la Disposicion DNPDP 11/2006 y la 9/2008, que ya **no** estan vigentes. Anexo I: A Recoleccion, B Control de acceso, C Control de cambios, D Respaldo y recuperacion, E Gestion de vulnerabilidades, F Destruccion, G Incidentes, H Entornos de desarrollo.
- **CIS Controls v8**: referencia tecnica internacional que muchos seguros usan de base.

Esto ordena evidencia; **no es asesoramiento legal ni una certificacion.**

**Como se comprueba cada control.**

| Tipo | Ejemplos | De donde sale |
|---|---|---|
| Automatico (14) | MFA en administradores y usuarios, pocas cuentas administradoras, inventario con responsable, escaneos periodicos, criticas y explotadas (KEV) abiertas, cierres verificados, registros recientes, reglas de deteccion, cadena de custodia integra, playbooks de respuesta, casos sin abandonar, simulacros de respuesta recientes, soberania | datos reales de `auth`, `asset`, `scan`, `vuln`, `siem`, `soar`, `purple` y `case-service`, consultados con un JWT de servicio de la organizacion |
| Manual (14) | respaldos con restauracion probada, copia fuera de linea, capacitacion, EDR, filtrado de correo, cifrado, inscripcion ante la AAIP, politica de seguridad, proveedores | una persona (admin o soc_manager) lo **declara**: respuesta (si / parcial / no), nota de al menos 10 letras y vigencia de 6, 12 o 24 meses |

**Reglas que no se rompen.**

- Si una fuente no responde, el control queda **sin datos**; nunca "cumple".
- **Verificado** y **declarado** no se mezclan: hay dos puntajes ("Verificado por TERO" y "Con lo declarado"), y lo pendiente cuenta como no cumplido en el total.
- Una declaracion **no pisa** lo que TERO ve: solo completa un control automatico cuando TERO no tiene datos (por ejemplo, administradores que entran por SSO, donde el MFA lo controla el proveedor de identidad).
- Una declaracion vencida deja de contar.
- Cada declaracion, foto y atestado queda anotado en la cadena de custodia (`compliance.declaration`, `compliance.declaration_removed`, `compliance.snapshot`, `compliance.attestation`). De la nota solo se guarda su huella en la cadena.

**Cuestionario de ciberseguro.** 19 preguntas que casi todas las aseguradoras hacen, respondidas con la evidencia de arriba (Si / Parcial / No / Sin responder). Cada aseguradora tiene su formulario propio: es una base para completarlo, no un reemplazo. Se baja como CSV (`/compliance/questionnaire.csv`).

**Evolucion.** "Guardar foto de hoy" guarda el puntaje del momento; ademas `case-service` guarda una foto por organizacion cada 24 horas (`COMPLIANCE_SNAPSHOT_HOURS`, `0` la apaga). El grafico muestra los dos puntajes en el tiempo.

**Atestado firmado.** `GET /compliance/attestation` entrega un atestado `tero-attestation` de tipo `compliance` con cada control, su estado, de donde sale, las observaciones y el cuestionario, firmado con la clave de la cadena de custodia. Se comprueba sin TERO:

```
python verificar_evidencia.py atestado-cumplimiento.json
```

**Variables (.env).**

| Variable | Por defecto | Para que |
|---|---|---|
| `COMPLIANCE_SNAPSHOT_HOURS` | `24` | cada cuanto se guarda una foto automatica (`0` = nunca) |
| `AUTH_SERVICE_URL`, `ASSET_SERVICE_URL`, `SCAN_SERVICE_URL`, `VULN_SERVICE_URL`, `SIEM_SERVICE_URL`, `SOAR_SERVICE_URL`, `PURPLE_SERVICE_URL` | nombres de servicio de Docker | solo si los servicios no estan en la red de compose |

**Limites honestos.**

- El puntaje es una ayuda para ordenar el trabajo; no asegura el resultado de una auditoria ni de una renovacion de seguro.
- Lo verificado prueba el estado de TERO en el momento de la consulta, no lo anterior ni lo posterior.
- TERO solo ve lo que gestiona: un equipo que no esta en el inventario o un usuario que entra por SSO queda fuera de lo verificado (se dice en el detalle).
- Lo declarado lo afirma una persona; TERO no puede comprobarlo.
- Los umbrales (por ejemplo "hasta 3 administradores o un tercio" o "criticas abiertas hace mas de 30 dias") son referencias razonables, no un requisito legal.

## 5. Simulacros medibles de respuesta

**Que resuelve.** Tener un plan de respuesta a incidentes no prueba que el equipo sepa usarlo. Un auditor o una aseguradora preguntan "lo probaron alguna vez, y cuanto tardaron?". TERO hace el ejercicio y deja la respuesta medida y firmada.

**Como funciona.**

1. En **Confianza y evidencia > Simulacros** un administrador o un responsable del SOC elige un escenario (phishing, ransomware, fuerza bruta o exfiltracion de datos) y toca "Empezar simulacro".
2. `purple-service` pone en el SIEM **una sola linea de registro de ejemplo**, rotulada `[SIMULACRO TERO]` (equipo `simulacro-tero`, IP de documentacion `192.0.2.10`). Una regla propia del simulacro (`[SIMULACRO] ...`, con la etiqueta `tero-drill`) la detecta y crea una alerta marcada como simulacro.
3. El equipo hace lo que haria en un incidente real: **reconoce** la alerta en SIEM y la **cierra con una nota** de lo hecho. El reloj corre desde que se inyecto el evento.
4. TERO toma los tiempos de la **cadena de custodia** (eventos `alert.created` y `alert.status_changed` con su hora), que no se puede alterar despues, y calcula el puntaje.
5. El resultado queda en el historial y como atestado firmado (`GET /drills/{id}/attestation` en `case-service`, tipo `drill`) que se verifica sin TERO:

```
python verificar_evidencia.py prueba-simulacro.json
```

**Puntaje (0 a 100).** Los umbrales estan a la vista en la pantalla.

| Parte | Puntos | Como se gana |
|---|---|---|
| Deteccion | 30 | el SIEM crea la alerta |
| Reconocer | 40 | hasta 15 min: 40, hasta 1 h: 30, hasta 4 h: 20, despues: 10 |
| Cerrar con nota | 30 | hasta 4 h: 30, hasta 24 h: 20, despues: 10; sin una nota de al menos 10 letras, la mitad |

Preparado desde 80, parcial desde 50, insuficiente por debajo. El puntaje de preparacion es el promedio de los ultimos 5 simulacros. Si nadie cierra la alerta en 24 horas, el simulacro vence y se puntua lo que paso. Solo puede haber un simulacro en curso por organizacion.

**Que garantiza que es seguro.**

- No ejecuta ninguna tecnica de ataque ni toca ningun equipo: solo agrega una linea de registro inofensiva.
- **No dispara respuestas reales.** `siem-service` omite los playbooks de SOAR y el enriquecimiento externo para las alertas de reglas con la etiqueta `tero-drill`; la pantalla solo informa cuantos playbooks habrian respondido.
- Las reglas del simulacro no cuentan como cobertura de deteccion real en el control de cumplimiento correspondiente.

**Conexion con las otras funciones.** Cada simulacro deja `drill.started`, `drill.completed` o `drill.cancelled` en la cadena de custodia. En **Cumplimiento** el control `INC-03` (simulacros de respuesta con tiempos medidos) se comprueba solo: cumple si el ultimo simulacro fue hace 180 dias o menos y saco 70 puntos o mas; es parcial si es mas viejo o salio flojo; no cumple si nunca se hizo. La pregunta Q19 del cuestionario de ciberseguro se responde con esa evidencia.

**Variables (.env).**

| Variable | Por defecto | Para que |
|---|---|---|
| `DRILL_EXPIRE_HOURS` | `24` | horas hasta que un simulacro sin cerrar vence |
| `DRILL_POLL_SECONDS` | `20` | cada cuanto `purple-service` revisa los simulacros en curso |
| `SIEM_INGEST_TOKEN` | el del `.env` | `purple-service` lo usa para enviar el evento de ejemplo al SIEM |
| `SIEM_SERVICE_URL`, `CASE_SERVICE_URL`, `SOAR_SERVICE_URL` | nombres de servicio de Docker | solo si los servicios no estan en la red de compose |

**Limites honestos.**

- El simulacro prueba que el camino evento -> alerta funciona y que **las personas responden a tiempo**. **No prueba las reglas de deteccion reales de tu organizacion**: para eso esta el analisis de cobertura ATT&CK.
- Los tiempos miden lo que se hizo en el SIEM; si el equipo actua fuera de TERO (por telefono, por ejemplo) y no lo registra en la alerta, no se ve.
- Los umbrales de puntaje son una referencia razonable, no un estandar. Si tu equipo trabaja por guardias, ajusta las expectativas antes de interpretar el numero.
- Quien reconoce o cierra la alerta puede hacerlo sin hacer nada de verdad: el simulacro mide tiempos y notas, no la calidad de la respuesta.
- Para que existan la tabla y los endpoints nuevos hay que reconstruir las imagenes (`--compilar`).
