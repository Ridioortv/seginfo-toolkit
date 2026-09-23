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

## Lo que falta para automatizar esto con Mercado Pago

Hoy estos tres comandos se corren a mano cuando el operador confirma un
pago. Para que un webhook de Mercado Pago llame automáticamente a
`/admin/clients/<license_key>/extend` en cada pago aprobado, falta:

1. Las credenciales de Mercado Pago del operador (access token de la
   aplicación).
2. Decidir cómo se cobran los USD 250/mes: Mercado Pago no tiene
   suscripción recurrente nativa en USD (su API de "Planes y
   Suscripciones" cobra en moneda local, ARS para Argentina) -- hay que
   elegir entre cobrar el equivalente en ARS al tipo de cambio del día,
   o sumar Stripe/PayPal en paralelo para poder cobrar en USD
   directamente.
3. Un endpoint nuevo en este servidor (`POST /webhooks/mercadopago`,
   autenticado con el secreto que Mercado Pago firma en cada
   notificación) que reciba el webhook, identifique de qué cliente es
   el pago, y llame internamente al mismo código que usa
   `/admin/clients/{id}/extend`.

Ninguno de los tres requiere tocar el resto de esta arquitectura --
encajan en el mismo servidor una vez que el operador tenga esas
credenciales y haya decidido el punto 2.
