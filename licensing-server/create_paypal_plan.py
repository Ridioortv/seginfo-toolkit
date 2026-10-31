"""Crea (una sola vez) el producto y el plan de PayPal de TERO Security:
USD 250 cada 30 dias, renovacion automatica. Imprime el PAYPAL_PLAN_ID que
hay que pegar en licensing-server/.env.

Uso (desde licensing-server/, con PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET /
PAYPAL_ENV ya cargados en el entorno o en .env):
    python create_paypal_plan.py            # USD 250 / 30 dias
    python create_paypal_plan.py --price 250 --days 30

No guarda ni imprime tus credenciales. Cambiar PAYPAL_ENV a "live" para crear
el plan en produccion (los planes de sandbox y live son distintos)."""
import argparse
import asyncio
import os
import sys

import httpx

from app import paypal


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def _write_env_value(path: str, key: str, value: str) -> bool:
    """Pone KEY=value en el .env (reemplaza la linea si existe, si no la agrega)."""
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    done = False
    for i, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[i] = f"{key}={value}"
            done = True
    if not done:
        lines.append(f"{key}={value}")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return True


async def main(price: str, days: int) -> int:
    if not paypal.is_configured():
        print("Faltan PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET (licensing-server/.env).")
        return 1
    async with httpx.AsyncClient(timeout=20) as client:
        token = await paypal._get_access_token(client)
        try:
            plan_id = await paypal.create_plan(client, token, price, days)
        except paypal.PayPalError as exc:
            print(exc)
            return 1
    print(f"Plan creado en PayPal ({paypal.PAYPAL_ENV}): USD {price} cada {days} dias")
    print(f"PAYPAL_PLAN_ID={plan_id}")
    if _write_env_value(".env", "PAYPAL_PLAN_ID", plan_id):
        print("Ya lo guarde en licensing-server/.env (linea PAYPAL_PLAN_ID). Reinicia el servidor de licencias.")
    else:
        print("No encontre licensing-server/.env: copia la linea de arriba a tu .env y reinicia el servidor.")
    return 0


if __name__ == "__main__":
    _load_dotenv()
    # los modulos leen el entorno al importarse: recargar con el .env ya cargado
    import importlib
    importlib.reload(paypal)
    ap = argparse.ArgumentParser()
    ap.add_argument("--price", default="250")
    ap.add_argument("--days", type=int, default=30)
    a = ap.parse_args()
    sys.exit(asyncio.run(main(a.price, a.days)))
