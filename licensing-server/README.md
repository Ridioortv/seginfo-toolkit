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

Necesitás: un VPS con Docker (DigitalOcean, Hetzner, etc. -- cualquiera
de ~$5-6 USD/mes alcanza de sobra) y, para producción de verdad, TLS
delante (Caddy o nginx con Let's Encrypt) porque `ADMIN_TOKEN` viaja en
texto plano en el header `Authorization` de los endpoints `/admin/*`.

```bash
cd licensing-server
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python generate_keys.py
# copia LICENSE_SIGNING_PRIVATE_KEY a .env (ver .env.example) -- NUNCA a un cliente
# copia LICENSE_SERVER_PUBLIC_KEY al .env.example del repo principal
# (o al .env de cada instalación antes de armar el .rar)

cp .env.example .env
# completar ADMIN_TOKEN (un secreto largo random propio) y
# LICENSE_SIGNING_PRIVATE_KEY (el que imprimió generate_keys.py)

docker compose up -d --build
```

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
