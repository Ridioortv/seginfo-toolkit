"""Recuperar una contrasena SIN mail, desde la maquina donde corre TERO Security.

    docker compose exec auth-service python -m app.cli_password correo@empresa.com

Imprime un link de un solo uso (vale 30 min) para elegir la contrasena nueva. Hace falta poder
ejecutar docker en el servidor: eso ya es acceso de administrador de la instalacion, asi que no
abre ninguna puerta nueva. Es lo mismo que "Restablecer contrasena" en Usuarios y roles, pero sirve
tambien cuando la ultima persona administradora olvido su clave o no hay SMTP configurado.
No imprime ni acepta contrasenas (no quedan en el historial de la terminal)."""
import asyncio
import sys

from app import password_reset, services
from backend.shared.database import SessionLocal


async def generar_link(email: str) -> tuple[int, str]:
    async with SessionLocal() as db:
        user = await services.get_user_by_email(db, email.strip())
        if user is None or not user.is_active:
            return 1, "No hay una cuenta activa con ese email."
        if user.hashed_password is None:
            return 1, "Esa cuenta entra con Google/SSO: no tiene contrasena para restablecer."
        url = password_reset.reset_url(password_reset.create_reset_token(user))
        await services.record_audit_event(db, "consola-del-servidor", "user.password_reset_link_by_console", user.email)
        await db.commit()
    return 0, url


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 2
    codigo, texto = asyncio.run(generar_link(argv[1]))
    if codigo:
        print(texto, file=sys.stderr)
        return codigo
    print(f"\nLink para elegir la contrasena nueva (vale {password_reset.RESET_TOKEN_MINUTES} minutos, un solo uso):\n")
    print(texto)
    print("\nAbrilo en el navegador. Si TERO se abre desde otra direccion, cambia FRONTEND_URL en .env.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
