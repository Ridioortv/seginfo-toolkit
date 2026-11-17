# Olvide mi contrasena y MFA al crear la cuenta

En la pantalla de entrada: **¿Olvidaste tu contrasena?** -> email -> link de un solo uso (30 min). Requiere
`SMTP_HOST` en `.env`; sin mail, un administrador genera el link en **Usuarios y roles -> Restablecer
contrasena**. Ya adentro: **Seguridad de la cuenta -> Cambiar contrasena**. Detalle y topes en
`backend/services/auth-service/app/password_reset.py`.

Sin mail (o si la persona administradora olvido su propia clave) el link se genera desde el servidor y se muestra en
pantalla: en Windows con `TERO Security - Restablecer contrasena.exe`, en Linux Mint y macOS con
`./tero-restablecer-clave.sh correo@empresa.com` (equivale a
`docker compose exec auth-service python -m app.cli_password correo@empresa.com`). La pantalla "Olvidaste tu
contrasena" avisa cuando la instalacion no tiene el envio de mails configurado.

Al **crear una cuenta**, el paso para escanear el QR del MFA queda abierto 2 horas (`MFA_SETUP_TOKEN_MINUTES`,
de 5 a 1440) y acepta un codigo con hasta ~1 minuto de diferencia de reloj.

Para dejar el correo andando (Gmail con clave de aplicacion) hay un script que manda un mail de prueba, guarda
`SMTP_*` en `.env` y reinicia auth-service; si el envio falla no toca el `.env`. En Windows:
`powershell -ExecutionPolicy Bypass -File tools\configurar-correo.ps1`. En Linux Mint: `./configurar-correo.sh`.
Solo reciben el mail los usuarios que tienen contrasena (los que entran solo con Google no).
