# Puesta en produccion de TERO (lista de verificacion)

Esta lista cubre lo que **solo se puede hacer en tu servidor/dominio**. El codigo ya
trae: puertos cerrados por defecto (127.0.0.1), reinicio automatico y healthchecks en
Docker, rechazo de secretos de ejemplo cuando `ENVIRONMENT` no es `development`,
sesiones cortas (15 min), MFA, auditoria y cadena de custodia firmada.

## 1. Secretos y modo produccion
1. `powershell -File tools\rotar-secretos.ps1` genera secretos nuevos y largos.
2. En `.env`: `ENVIRONMENT=production`, `CORS_ALLOWED_ORIGINS=https://tero.tudominio.com`.
   Con `production`, los servicios **no arrancan** si queda algun `changeme`.
3. No cambies `CUSTODY_SIGNING_SEED` ni `ENCRYPTION_KEY` despues de tener datos:
   invalidaria la cadena de custodia y las credenciales guardadas.

## 2. HTTPS (obligatorio)
Publica TERO solo detras de un proxy con TLS (Caddy es lo mas simple: certificado
automatico con Let's Encrypt). Ejemplo `Caddyfile`:

```
tero.tudominio.com {
    reverse_proxy 127.0.0.1:5173
}
```

Las APIs (puertos 8001-8015) quedan en 127.0.0.1; el frontend las consume por el
mismo host. Si las expones bajo otro dominio, agregalo a `connect-src` en
`frontend/nginx.conf` y a `CORS_ALLOWED_ORIGINS`, y reconstruye el frontend.
No abras Postgres (5432), Redis (6379) ni OpenSearch (9200) al exterior.

## 3. Reconstruir las imagenes
Las correcciones del codigo llegan a tu instancia **solo al reconstruir**:

```
docker compose build
docker compose up -d
```

## 4. Respaldos
- Diario: `tools/respaldar.sh` (Linux) o `tools/respaldar.ps1` (Windows). Ver `docs/runbook.md`.
- Copia los `.dump` y el `.env` (cifrado) fuera del servidor.
- Prueba `tools/restaurar.*` en una copia de prueba antes de confiar en ellos.

## 5. Correo (recuperar contrasena / notificaciones)
Completa `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` en `.env`.
Sin SMTP la app funciona, pero "Olvide mi contrasena" no envia correos.

## 6. Pruebas finales con datos reales (no automatizables)
- Escaneo real + re-escaneo para el **cierre verificado**.
- Modo aislado de soberania (`docker-compose.aislado.yml`) en tu Docker.
- Pago real de prueba con MercadoPago/PayPal.
- AntiEstafa AR: cargar la URL de TERO y el token de ingesta en esa app.
- Pentest externo y revision legal de Terminos y Politica de privacidad antes de vender.

## 7. Limites conocidos
- Un usuario desactivado conserva su token de acceso hasta 15 min (ajustable con
  `ACCESS_TOKEN_EXPIRE_MINUTES`).
- 14 de los 28 controles de cumplimiento son manuales por diseno (requieren evidencia humana).
- `infra/terraform` e `infra/k8s` son plantillas: revisar hallazgos de seguridad antes de usarlas.
