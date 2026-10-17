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
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        base = paypal._base_url()

        r = await client.post(
            f"{base}/v1/catalogs/products", headers=headers,
            json={"name": "TERO Security", "type": "SERVICE", "category": "SOFTWARE"},
        )
        if r.status_code >= 400:
            print("PayPal rechazo la creacion del producto:", r.status_code, r.text[:400])
            return 1
        product_id = r.json()["id"]

        r = await client.post(
            f"{base}/v1/billing/plans", headers=headers,
            json={
                "product_id": product_id,
                "name": f"TERO Security USD {price} cada {days} dias",
                "billing_cycles": [{
                    "frequency": {"interval_unit": "DAY", "interval_count": days},
                    "tenure_type": "REGULAR",
                    "sequence": 1,
                    "total_cycles": 0,
                    "pricing_scheme": {"fixed_price": {"value": price, "currency_code": "USD"}},
                }],
                "payment_preferences": {"auto_bill_outstanding": True, "payment_failure_threshold": 3},
            },
        )
        if r.status_code >= 400:
            print("PayPal rechazo la creacion del plan:", r.status_code, r.text[:400])
            return 1
        plan_id = r.json()["id"]
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
