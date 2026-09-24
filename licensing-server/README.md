# Servidor central de licencias de SentinelOps

Este servicio **no va dentro del `.rar`** que reciben los clientes. Lo
despliega el operador (Manu) en su propia infraestructura -- cualquier
VPS chico alcanza (1 vCPU / 512 MB de RAM sobra: unos pocos clientes
haciendo check-in una o dos veces por dia es un trafico minimo). Es la
fuente de verdad de qué organización tiene la suscripción al día,
porque el Postgres de cada instalación on-prem vive en la máquina del
propio cliente y no puede ser esa fuente de verdad (cualquier cliente
con acceso a su base podría "renovarse" gratis editándola a mano).

## Cómo funciona

1. Este servidor guarda, por `license_key`, hasta cuándo tiene pagado
   cada cliente (`subscription_expires_at`).
2. `GET /license/{license_key}/status` devuelve ese estado, **firmado**
   con una clave privada Ed25519 que sólo este servidor tiene.
3. Cada instalación on-prem (su `auth-service`) consulta ese endpoint
   periódicamente (ver `backend/shared/license_check.py`), verifica la
   firma con la clave pública (que sí viaja con el cliente, en su
   `.env`), y cachea el resultado en su propia base
   (`Organization.subscription_expires_at`/`license_last_checked_at`).
4. Si el cliente corta su salida a internet para siempre y se queda con
   el último estado "válido" cacheado, `is_org_active()` en
   `auth-service` lo detecta (más de `LICENSE_GRACE_DAYS` sin poder
   confirmar) y bloquea igual.

Sin este servidor desplegado (`LICENSE_SERVER_URL` vacío en el `.env`
del cliente), cada instalación sigue funcionando con el vencimiento
local únicamente, gestionado a mano por el operador vía
`POST /auth/organizations/{id}/subscription/extend` (requiere ser
`platform_admin`). Es decir: **este servidor es un endurecimiento
opcional, no un requisito para que el cobro mensual funcione hoy.**

## Desplegar

Necesitás: un VPS con Docker y un dominio (o subdominio) que apunte a
su IP -- Caddy (incluido en `docker-compose.yml`, ver mas abajo) le
pone TLS automático (Let's Encrypt) delante, imprescindible porque
`ADMIN_TOKEN` viaja en texto plano en el header `Authorization` de los
endpoints `/admin/*`. Cualquier VPS con Docker sirve (DigitalOcean,
Hetzner, ~$5-6 USD/mes). Este camino (y el de Google Cloud Free Tier,
mas abajo) piden tarjeta para verificar la cuenta -- si no tenés una,
o no te la aceptan, la sección **"Desplegar en Render + Neon (gratis,
sin tarjeta)"** es la alternativa: gratis para siempre, sin tarjeta en
ningún lado, a cambio de una demora de ~1 minuto si el servicio estuvo
15+ minutos sin uso.

```bash
cd licensing-server
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python generate_keys.py
# copia LICENSE_SIGNING_PRIVATE_KEY a .env (ver .env.example) -- NUNCA a un cliente
# copia LICENSE_SERVER_PUBLIC_KEY al .env.example del repo principal
# (o al .env de cada instalación antes de armar el .rar)

cp .env.example .env
# completar ADMIN_TOKEN (un secreto largo random propio),
# LICENSE_SIGNING_PRIVATE_KEY (el que imprimió generate_keys.py) y
# LICENSE_SERVER_DOMAIN (el dominio que ya apunta a este VPS -- Caddy
# lo necesita para pedir el certificado, una IP sola no le alcanza)

docker compose up -d --build
```

## Desplegar en Google Cloud Free Tier (gratis para siempre)

Instancia `e2-micro` (1 vCPU compartida, 1GB RAM) -- de sobra para este
servicio (SQLite + FastAPI, trafico minimo). Gratis para siempre
mientras se respeten estas condiciones (que ya están abajo).

### 1. Crear la cuenta y el proyecto

En https://console.cloud.google.com/freetrial/signup te va a pedir una
tarjeta (no cobra nada mientras no salgas del free tier a mano). Creá
un proyecto nuevo (cualquier nombre).

### 2. Reservar una IP externa estática

Sin esto, la IP del VPS puede cambiar si se reinicia -- rompería el DNS
apenas pase. Es gratis mientras esté asignada a una instancia
corriendo (cobra solo si queda "suelta", sin usar).

Consola: **VPC network -> IP addresses -> Reserve external static
address** (región: alguna de `us-west1`, `us-central1` o `us-east1` --
son las únicas elegibles para el free tier).

### 3. Crear la VM

Consola: **Compute Engine -> VM instances -> Create instance**.

- Región: la misma que la IP reservada (`us-west1`, `us-central1` o
  `us-east1`) -- fuera de esas tres, se cobra.
- Tipo de máquina: **e2-micro**.
- Boot disk: Ubuntu 22.04 LTS o más nueva, disco estándar (no SSD) de
  hasta 30GB -- SSD o más tamaño sale de lo gratis.
- Redes -> IP externa: elegí la IP estática que reservaste en el paso 2.
- Firewall: tildá "Allow HTTP traffic" y "Allow HTTPS traffic" (abre
  los puertos 80/443, los que usa Caddy).
- Desactivá cualquier opción de backups/snapshots automáticos y
  monitoring adicional -- son las que más rápido generan cargos por
  fuera del free tier.

### 4. Apuntar tu dominio

En el DNS de tu dominio (el que sea -- no hace falta comprar uno nuevo
si ya tenés alguno; si no tenés, un subdominio gratis de
[DuckDNS](https://www.duckdns.org/) también sirve), creá un registro
**A** apuntando a la IP estática del paso 2. Esperá unos minutos a que
propague antes del paso 6 (Caddy necesita poder resolverlo para pedir
el certificado).

### 5. Conectarte e instalar Docker

Desde la consola de Google Cloud, botón **SSH** al lado de la
instancia (abre una terminal en el navegador, no hace falta configurar
nada más):

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# cerrá y volvé a abrir la sesion SSH para que el grupo tome efecto
git clone https://github.com/Ridioortv/seginfo-toolkit.git
cd seginfo-toolkit/licensing-server
```

### 6. Configurar y levantar

Seguí el bloque de comandos de la sección "Desplegar" de más arriba
(`generate_keys.py`, completar `.env` -- ADMIN_TOKEN,
LICENSE_SIGNING_PRIVATE_KEY y `LICENSE_SERVER_DOMAIN` con el dominio
del paso 4) y despues `docker compose up -d --build`. A los pocos
segundos Caddy pide el certificado solo -- `docker compose logs -f
caddy` para ver que diga "certificate obtained successfully".

### El límite a vigilar: egreso de red

El free tier de GCP incluye 1GB/mes de salida a internet gratis; de
ahí en adelante cobra (~$0.12/GB). Para este servicio (un JSON chico
por cada check-in de licencia, una o dos veces por día por cliente) es
un margen enorme -- no hay riesgo real de pasarlo salvo que tengas
cientos de clientes.

## Desplegar en Render + Neon (gratis, sin tarjeta)

Alternativa completa a los dos caminos de arriba para cuando no tenés
tarjeta o no te la aceptan (el error `OR_BACR2_59` de Google Cloud,
por ejemplo). Nada de esto pide tarjeta en ningún paso. La contra:
Render "duerme" el servicio a los 15 minutos sin requests -- el
próximo check-in de un cliente, o el próximo webhook de Mercado Pago,
tarda ~1 minuto extra en responder mientras se despierta (Mercado Pago
reintenta los webhooks solo si no le mandas un 200 a tiempo, asi que
no se pierde el evento, solo se demora).

Este camino no usa Caddy ni `LICENSE_SERVER_DOMAIN` -- Render te da un
dominio propio (`https://tu-servicio.onrender.com`) con TLS automático
incluido.

### 1. Base de datos: Neon (Postgres gratis, sin tarjeta)

1. Entrá a [neon.tech](https://neon.tech) y creá una cuenta (con
   GitHub o Google alcanza, no pide tarjeta).
2. Creá un proyecto nuevo (cualquier nombre y región te sirven).
3. En el dashboard del proyecto, pestaña **Connection Details**, copiá
   la **Connection string** completa (arranca con `postgresql://` y ya
   incluye `?sslmode=require` al final) -- vas a usarla como
   `DATABASE_URL` en el paso 3.

### 2. Generar las claves de firma (una sola vez, en tu máquina)

```bash
cd licensing-server
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python generate_keys.py
```

Guardá los dos valores que imprime: `LICENSE_SIGNING_PRIVATE_KEY` (va
en Render, paso 3 -- nunca a un cliente) y `LICENSE_SERVER_PUBLIC_KEY`
(va en el `.env.example` del repo principal / en el `.env` de cada
instalación on-prem antes de armar el `.rar`).

### 3. Servicio: Render (gratis, sin tarjeta)

1. Entrá a [render.com](https://render.com) y creá una cuenta (con
   GitHub alcanza, no pide tarjeta para el plan free).
2. **New -> Web Service**, elegí el repo `Ridioortv/seginfo-toolkit`
   (dale permiso a Render sobre el repo si te lo pide).
3. Completá:
   - **Root Directory**: `licensing-server`
   - **Runtime**: Docker (Render detecta el `Dockerfile` solo)
   - **Instance Type**: **Free**
4. En **Environment Variables** agregá:
   - `ADMIN_TOKEN` -- un secreto largo random propio (ej.
     `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`)
   - `LICENSE_SIGNING_PRIVATE_KEY` -- el del paso 2
   - `DATABASE_URL` -- la connection string de Neon del paso 1 (al
     estar seteada, este servidor usa Postgres en vez de SQLite solo)
   - `MERCADOPAGO_ACCESS_TOKEN`, `MERCADOPAGO_PLAN_ID` -- los tuyos
     (ver "Cobrar con Mercado Pago" más abajo si todavía no los tenés)
   - `MERCADOPAGO_WEBHOOK_SECRET` -- lo completás en el paso 5, dejalo
     vacío por ahora
   - `MERCADOPAGO_BACK_URL` -- opcional, default sirve
5. **Create Web Service**. Render clona el repo, hace `docker build` y
   despliega -- tarda unos minutos la primera vez. Cuando el estado
   pase a **Live**, arriba de todo vas a ver la URL
   (`https://tu-servicio.onrender.com`).

No hace falta tocar `PORT`: Render la inyecta sola y el `Dockerfile` ya
la respeta (ver `ENV PORT` ahí).

### 4. Confirmar que responde

```bash
curl https://tu-servicio.onrender.com/health
```

Si tardó ~1 minuto en responder la primera vez, es el "despertar" del
plan free descripto arriba -- normal.

### 5. Registrar el webhook de Mercado Pago

Con el servicio ya arriba, seguí el paso "3. Webhook" de la sección
"Cobrar con Mercado Pago" más abajo, usando
`https://tu-servicio.onrender.com/webhooks/mercadopago` como URL del
webhook. El panel de Mercado Pago te va a mostrar ahí la "clave
secreta" -- volvé a Render, pegala en la variable
`MERCADOPAGO_WEBHOOK_SECRET` y guardá (Render redeploya solo al
cambiar una variable).

### El límite a vigilar: horas de instancia

El plan free de Render da 750 horas/mes de instancia activa -- un solo
servicio corriendo todo el mes usa ~720, así que sobra margen aunque
nunca se duerma. Si tenés más de un servicio free en la misma cuenta,
las horas se comparten entre todos.

## Gestionar clientes

```bash
# Crear un cliente nuevo (30 días desde ahora por defecto)
curl -X POST https://tu-servidor:8443/admin/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"org_name": "ACME SA", "days": 30}'
# -> devuelve license_key: copiarla al LICENSE_KEY del .env de ESE cliente

# Renovar tras confirmar un pago (extiende desde el vencimiento actual,
# no pierde días si se renueva antes de que venza)
curl -X POST https://tu-servidor:8443/admin/clients/<license_key>/extend \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"days": 30}'

# Ver todos los clientes y cuándo vence cada uno
curl https://tu-servidor:8443/admin/clients -H "Authorization: Bearer $ADMIN_TOKEN"

# Cortar el acceso YA (fraude, chargeback, etc -- no para el vencimiento normal)
curl -X POST https://tu-servidor:8443/admin/clients/<license_key>/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Cobrar con Mercado Pago (automático, a tu cuenta, en pesos)

Gateway activo por ahora: los clientes pagan en **ARS**, a tu propia
cuenta de Mercado Pago, vía **Preapproval** (suscripciones). El flujo
completo está implementado en `app/mercadopago.py` + los endpoints
`POST /admin/clients/{license_key}/mercadopago-subscription-link` y
`POST /webhooks/mercadopago`. A diferencia de PayPal, Mercado Pago no
tiene un endpoint para verificar la firma del webhook por vos -- este
servidor la calcula a mano (HMAC-SHA256, ver el docstring de
`verify_webhook_signature` en `app/mercadopago.py`) y, aun verificada,
**siempre** vuelve a pedirle el recurso completo a la API de Mercado
Pago antes de extender nada (nunca confía en el cuerpo del webhook).

Para dejarlo funcionando hacen falta 3 pasos, todos una sola vez (no
por cliente):

### 1. Access token de tu aplicación

En https://www.mercadopago.com.ar/developers/panel/app creá (o
abrí) tu aplicación -- te da un access token de **prueba** (para
probar sin plata real, con las tarjetas/usuarios de test que da el
panel) y otro de **producción**. A diferencia de PayPal es el mismo
token el que decide sandbox o no (no hay una URL distinta). Completá
en `.env`:

```
MERCADOPAGO_ACCESS_TOKEN=TEST-...   # el de produccion recien cuando probaste todo el flujo abajo
```

### 2. El plan de suscripción en ARS cada 30 días

Se crea una sola vez (después todos los clientes se suscriben al mismo
plan). Elegí el monto en pesos que corresponda a los USD 250 (al tipo
de cambio que prefieras -- este servidor no hace esa conversión sola,
la fijás vos al crear el plan):

```bash
curl -X POST https://api.mercadopago.com/preapproval_plan \
  -H "Authorization: Bearer $MERCADOPAGO_ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "reason": "SentinelOps mensual",
    "back_url": "https://tu-pagina-de-gracias-o-lo-que-sea.com",
    "auto_recurring": {
      "frequency": 30,
      "frequency_type": "days",
      "transaction_amount": 250000,
      "currency_id": "ARS"
    }
  }'
# -> anotá el "id" (2c9380...): ese es tu MERCADOPAGO_PLAN_ID en .env
# (250000 es un ejemplo -- ajustalo al tipo de cambio del dia)
# back_url es OBLIGATORIO aunque la documentacion de Mercado Pago no lo
# marque asi -- sin el, la API devuelve 400 "Back url is required".
# En Windows con PowerShell: "curl" es un alias de Invoke-WebRequest y
# rompe el escapado de comillas de este comando -- usar curl.exe (asi,
# explicito) o Invoke-RestMethod con -Headers/-Body en su lugar.
```

### 3. El webhook

En el panel de tu aplicación -> Webhooks -> Configurar notificaciones,
URL `https://tu-servidor/webhooks/mercadopago`, con al menos estos
eventos tildados: **Suscripciones** (`subscription_preapproval`) y
**Pagos de suscripciones** (`subscription_authorized_payment`). El
panel te muestra ahí la "clave secreta" -- eso va en
`MERCADOPAGO_WEBHOOK_SECRET` de `.env`.

Sin `MERCADOPAGO_WEBHOOK_SECRET` configurado, `/webhooks/mercadopago`
rechaza cualquier evento (no puede verificar sin él) -- es
intencional.

### Onboarding de cada cliente nuevo

```bash
# 1) crear el cliente en este servidor (igual que hoy)
curl -X POST https://tu-servidor:8443/admin/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"org_name": "ACME SA", "days": 30}'
# -> guarda la license_key para el .env de ESE cliente

# 2) generar el link de suscripción de Mercado Pago para ese cliente
# (payer_email es el mail con el que el cliente tiene/crea su cuenta de MP)
curl -X POST https://tu-servidor:8443/admin/clients/<license_key>/mercadopago-subscription-link \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"payer_email": "cliente@acme.com"}'
# -> devuelve init_point: se lo mandás al cliente
```

Cuando el cliente abre `init_point` y aprueba en Mercado Pago (con su
propia cuenta/tarjeta), Mercado Pago te factura a vos y dispara
`subscription_preapproval` contra `/webhooks/mercadopago`, que
reconfirma el estado "authorized" contra la API y extiende la licencia
solo. Cada 30 días, Mercado Pago vuelve a cobrar automáticamente y
dispara `subscription_authorized_payment`, que reconfirma el cobro
("processed") y extiende otros 30 días. Si el cliente cancela la
suscripción en Mercado Pago, no se dispara ningún cobro nuevo -- el
periodo ya pagado sigue corriendo hasta que venza (`is_org_active()`
bloquea en el día 30 como siempre), no se corta antes.

Si preferís seguir usando `/admin/clients/{id}/extend` a mano para
algún caso (renovar manualmente, cortesía, etc.), sigue funcionando
igual -- Mercado Pago es un camino automático en paralelo, no
reemplaza esos endpoints.

**Nota:** los nombres exactos de algunos campos de la API de Mercado
Pago (sobre todo en `authorized_payments`) pudieron cambiar desde que
se escribió esto -- antes de cobrar en producción, probá el flujo
completo una vez con el access token de **prueba** y un plan de bajo
monto, y confirmá en los logs (`docker compose logs -f
licensing-server`) que la licencia se extiende sola tras aprobar.

## Cobrar con PayPal (automático, a tu cuenta, en USD)

Gateway alternativo, ya implementado pero no el que estás usando por
ahora (elegiste Mercado Pago). Si más adelante querés cobrar en USD a
clientes fuera de Argentina, esto ya está listo para activar sin
tocar el resto de la arquitectura -- corre en paralelo al de Mercado
Pago, cada cliente puede tener su propio link de cualquiera de los
dos. Los USD 250/30 días se cobrarían vía **PayPal Subscriptions**, a
tu propia cuenta de PayPal -- no hace falta correr `/extend` a mano
salvo que quieras renovar manualmente un caso puntual. El flujo
completo ya está implementado en `app/paypal.py` + los endpoints
`POST /admin/clients/{license_key}/paypal-subscription-link` y
`POST /webhooks/paypal`. Para dejarlo funcionando hacen falta 3 pasos,
todos una sola vez (no por cliente):

### 1. Credenciales de tu app REST

En https://developer.paypal.com/dashboard/applications creá una app
(te da un `Client ID` y un `Secret`, separados para "Sandbox" -- para
probar sin plata real -- y "Live"). Completá en `.env`:

```
PAYPAL_CLIENT_ID=...
PAYPAL_CLIENT_SECRET=...
PAYPAL_ENV=sandbox   # cambiar a "live" recién cuando probaste todo el flujo abajo
```

### 2. El Billing Plan de $250 cada 30 días

Se crea una sola vez (después todos los clientes se suscriben al mismo
plan). Más simple vía API que a mano en el dashboard -- con el
`access_token` que te da el paso 1:

```bash
# 1) crear el "product" (una sola vez)
curl -X POST https://api-m.sandbox.paypal.com/v1/catalogs/products \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "SentinelOps", "type": "SERVICE", "category": "SOFTWARE"}'
# -> anotá el "id" (PROD-XXXX) de la respuesta

# 2) crear el plan de $250 USD cada 30 días sobre ese product
curl -X POST https://api-m.sandbox.paypal.com/v1/billing/plans \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "product_id": "PROD-XXXX",
    "name": "SentinelOps mensual",
    "billing_cycles": [{
      "frequency": {"interval_unit": "DAY", "interval_count": 30},
      "tenure_type": "REGULAR",
      "sequence": 1,
      "total_cycles": 0,
      "pricing_scheme": {"fixed_price": {"value": "250", "currency_code": "USD"}}
    }],
    "payment_preferences": {"auto_bill_outstanding": true}
  }'
# -> anotá el "id" (P-XXXX): ese es tu PAYPAL_PLAN_ID en .env
```

### 3. El webhook

En el dashboard de tu app (Apps & Credentials -> tu app -> Add
Webhook), URL `https://tu-servidor/webhooks/paypal`, con al menos estos
eventos tildados: `BILLING.SUBSCRIPTION.ACTIVATED` y
`PAYMENT.SALE.COMPLETED`. El dashboard te muestra el Webhook ID al
crearlo -- eso va en `PAYPAL_WEBHOOK_ID` de `.env`.

Sin `PAYPAL_WEBHOOK_ID` configurado, `/webhooks/paypal` rechaza
cualquier evento (no verifica sin él) -- es intencional, ver el
docstring de `verify_webhook_signature` en `app/paypal.py`.

### Onboarding de cada cliente nuevo

```bash
# 1) crear el cliente en este servidor (igual que hoy)
curl -X POST https://tu-servidor:8443/admin/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"org_name": "ACME SA", "days": 30}'
# -> guarda la license_key para el .env de ESE cliente

# 2) generar el link de suscripción de PayPal para ese cliente
curl -X POST https://tu-servidor:8443/admin/clients/<license_key>/paypal-subscription-link \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{}'
# -> devuelve approval_url: se lo mandás al cliente
```

Cuando el cliente abre `approval_url` y aprueba en PayPal, PayPal te
factura a vos los $250 y dispara `BILLING.SUBSCRIPTION.ACTIVATED` contra
`/webhooks/paypal`, que verifica la firma y extiende la licencia solo
-- sin que toques nada. Cada 30 días, PayPal vuelve a cobrar
automáticamente y dispara `PAYMENT.SALE.COMPLETED`, que extiende otros
30 días. Si el cliente cancela la suscripción en PayPal, el periodo ya
pagado sigue corriendo hasta que venza (no se corta antes) -- ahí deja
de renovarse solo y `is_org_active()` bloquea en el día 30 como
siempre.

Si preferís seguir usando `/admin/clients/{id}/extend` a mano para
algún caso (renovar manualmente, cortesía, etc.), sigue funcionando
igual -- PayPal es un camino automático en paralelo, no reemplaza esos
endpoints.
