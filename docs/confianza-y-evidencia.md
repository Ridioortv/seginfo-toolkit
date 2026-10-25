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
