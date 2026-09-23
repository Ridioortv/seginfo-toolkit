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

## Cobrar con PayPal (automático, a tu cuenta)

Los USD 250/30 días se cobran vía **PayPal Subscriptions**, a tu propia
cuenta de PayPal -- no hace falta correr `/extend` a mano salvo que
quieras renovar manualmente un caso puntual. El flujo completo ya está
implementado en `app/paypal.py` + los endpoints
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
