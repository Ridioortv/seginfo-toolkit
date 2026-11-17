# Integracion con AntiEstafa AR

**Que suma.** TERO cuida los equipos, los servidores y la red. [AntiEstafa AR](https://tecnoros.ar) (un servicio de tecnoros.ar) cubre lo que le llega **a las personas**: el WhatsApp falso del "gerente", el audio del "banco", el link de un proveedor trucho, el QR cambiado. Cuando un empleado revisa algo en AntiEstafa y da **ESTAFA** o **SOSPECHOSO**, AntiEstafa avisa a TERO y TERO abre una alerta, avisa al equipo y abre un caso.

```
Empleado ──► AntiEstafa AR ──► (resultado al empleado)
                 │ si da ESTAFA o SOSPECHOSO
                 ▼
   POST /integrations/antiestafa/events  (siem-service)
                 ▼
   reglas "AntiEstafa: ..." ──► alerta ──► SOAR (avisa al equipo + abre un caso) ──► cadena de custodia
                 ▼
   Cobertura ATT&CK (T1566) · Panel (tarjeta de estafas) · Integraciones (estado y campanas)
```

## Que datos llegan (privacidad)

Por defecto **no** llega el texto del mensaje ni lo que dice el audio. Llegan: veredicto y riesgo, canal (`mensaje`, `captura`, `audio`, `link`, `qr`, `bot`), senales detectadas, dominios de los links, tecnicas MITRE, una huella corta del texto y el id de la organizacion. Si la empresa pidio expresamente mandar el texto (`TERO_INCLUIR_TEXTO=true` del lado de AntiEstafa), TERO lo guarda recortado a 2000 caracteres.

TERO indexa el evento **campo por campo**: solo guarda los campos que espera (con tope de largo y de cantidad) y descarta el resto; nada de lo que manda el cliente se guarda tal cual.

## Como se conecta (3 pasos)

1. **Activar las reglas.** En **Integraciones > AntiEstafa AR**, un administrador o un responsable del SOC toca "Activar las reglas de AntiEstafa". Carga 4 reglas (no duplica las que ya existen):

   | Regla | Nivel | Cuando salta |
   |---|---|---|
   | AntiEstafa: estafa o phishing detectado por un empleado | alto | resultado ESTAFA (mensaje, captura, link, QR, bot) |
   | AntiEstafa: mensaje sospechoso reportado por un empleado | medio | resultado SOSPECHOSO |
   | AntiEstafa: estafa por audio o llamada (posible voz clonada) | critico | ESTAFA por audio |
   | AntiEstafa: la misma estafa llego varias veces (campana en curso) | alto | el mismo dominio o mensaje se reporto 3 o mas veces en 24 h |

   Las tres primeras son las reglas Sigma que entrega AntiEstafa, en el formato de TERO. Una diferencia a proposito: la regla de "estafa" **excluye los audios**, para que un audio no abra dos alertas y dos casos (lo toma la de voz clonada). La cuarta es de TERO.

2. **Publicar la ruta con HTTPS.** TERO corre en la red del cliente con los puertos solo en `127.0.0.1`. Para que AntiEstafa (que esta en internet) pueda avisar, publica **solo esa ruta** detras de un proxy con HTTPS. Ejemplo con Caddy, en un nombre de dominio exclusivo para esto:

   ```
   tero-avisos.empresa.com.ar {
       request_body {
           max_size 64KB
       }
       @aviso {
           method POST
           path /api/siem/integrations/antiestafa/events
       }
       handle @aviso {
           uri strip_prefix /api/siem
           reverse_proxy 127.0.0.1:8005
       }
       handle {
           respond 404
       }
   }
   ```

   Con eso desde internet solo se alcanza esa ruta; el resto de TERO sigue sin salir de la red. Si la PC no tiene IP publica, un tunel como Cloudflare Tunnel sirve con la misma regla de "solo esta ruta". Es una decision de seguridad de la empresa: exponer algo siempre suma riesgo; el token (paso 3) y el tope de tamano lo acotan, pero no lo eliminan.

3. **Cargar las variables en AntiEstafa.** En **Integraciones > AntiEstafa AR** escribe la direccion publica, toca "Mostrar el token" (solo administradores) y copia el bloque de variables al proyecto de Vercel de esa empresa:

   | Variable | Valor |
   |---|---|
   | `TERO_SIEM_URL` | `https://tero-avisos.empresa.com.ar/api/siem/integrations/antiestafa/events` |
   | `TERO_API_KEY` | el token de ingesta de la organizacion (`GET /logs/ingest-token`) |
   | `TERO_ORGANIZACION` | el id de la organizacion que muestra la pantalla |
   | `TERO_INCLUIR_TEXTO` | `false` (recomendado) |

   Despues `npm run tero:prueba` manda un evento marcado `[PRUEBA]`. TERO responde `201` con `"test": true` y la pantalla muestra "Conexion comprobada". **Un evento de prueba no abre alertas ni casos**: prueba la conexion, no las reglas. Para probar las reglas de punta a punta hace falta un aviso real (por ejemplo, revisar en AntiEstafa un mensaje de estafa conocido).

El token es **por organizacion**: solo vale para la organizacion para la que se genero (no puede escribir en otra). Se manda en `Authorization: Bearer <token>` o en `X-Ingest-Token`. Tratalo como una contrasena.

## Que pasa cuando llega un aviso

1. TERO valida el token y arma el documento (si el evento no es de AntiEstafa o le falta el veredicto, responde `422`).
2. Lo guarda en el SIEM y lo cruza con las reglas: abre la **alerta** (y deja `alert.created` en la cadena de custodia).
3. **SOAR** corre sus playbooks segun el nivel: los que vienen incluidos ("Notificar al equipo SOC" y "Crear caso de incidente", desde nivel medio) avisan al equipo y abren un **caso** con su plazo segun la prioridad. No hace falta un playbook propio; uno nuevo duplicaria los casos.
4. Si el mismo dominio o el mismo mensaje (huella) llega **3 o mas veces en 24 h**, TERO abre una alerta de **campana** (una sola vez por dominio o mensaje) y avisa por el mismo camino. Se pueden cambiar los numeros con `ANTIESTAFA_CAMPAIGN_REPORTS` y `ANTIESTAFA_CAMPAIGN_HOURS`.
5. **Purple Team**: las reglas llevan la etiqueta `attack.t1566`, asi que la tecnica **Phishing (T1566)** deja de figurar como brecha de deteccion.
6. **Panel**: aparece la tarjeta "Estafas reportadas (7 dias)" cuando la integracion esta en uso. En Integraciones se ven los avisos por canal y resultado, los dominios mas reportados y las campanas en curso.

## Variables (.env de TERO)

| Variable | Por defecto | Para que |
|---|---|---|
| `ANTIESTAFA_CAMPAIGN_REPORTS` | `3` | reportes del mismo dominio o mensaje para considerarlo una campana |
| `ANTIESTAFA_CAMPAIGN_HOURS` | `24` | ventana para contar esos reportes |
| `SIEM_INGEST_TOKEN` | el del `.env` | de este token maestro se deriva el token de cada organizacion |

## Limites honestos

- **Detecta lo que las personas reportan.** No lee el correo ni el WhatsApp de nadie, no abre links y no bloquea nada. Si nadie revisa un mensaje en AntiEstafa, TERO no se entera. Por eso la cobertura de T1566 que se cuenta en Purple Team es una **deteccion por reporte humano**, no una proteccion automatica de correo.
- **No bloquea dominios.** TERO hoy no tiene una accion de SOAR para dominios (solo IP y host). Los dominios reportados quedan a la vista para cargarlos a mano en el firewall o el filtro de correo.
- **Cuenta reportes, no personas.** AntiEstafa no manda quien revisa (a proposito, por privacidad), asi que "3 reportes" pueden venir de una sola persona insistente. El aviso de campana es una pista, no una prueba.
- **El aviso a "toda la empresa"** lo recibe el equipo de seguridad por los canales de notificacion de TERO; TERO no manda correos al personal.
- Los eventos de prueba no abren alertas. El contador de "ultimo evento recibido" se guarda en memoria y se reinicia con el servicio.
- Falsos positivos: un mensaje legitimo con apuro o links acortados puede dar SOSPECHOSO. Cada regla lo aclara en su descripcion.
- Probado con los eventos de ejemplo de AntiEstafa y con la suite de pruebas de TERO; todavia no con una instalacion real de AntiEstafa en Vercel conectada a internet.
- Para que el endpoint nuevo exista hay que reconstruir la imagen del SIEM (`--compilar`).
