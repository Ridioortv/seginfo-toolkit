"""Almacenamiento de este servidor: SQLite plano (stdlib, sin drivers
async) -- el trafico esperado es minimo (unos pocos clientes haciendo
check-in una o dos veces por dia, mas los pocos requests admin que hace
el operador a mano), asi que Postgres seria sobre-ingenieria para lo que
es, en el fondo, una tabla con un puñado de filas. FastAPI corre las
rutas `def` (sync, no `async def`) en un threadpool, asi que esto no
bloquea el event loop."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.getenv("LICENSING_DB_PATH", "./licensing.db")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                license_key TEXT PRIMARY KEY,
                org_name TEXT NOT NULL,
                subscription_expires_at TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                paypal_subscription_id TEXT
            )
            """
        )
        # paypal_subscription_id se usa para encontrar que cliente
        # corresponde a un webhook de PayPal cuyo evento no trae de
        # vuelta el custom_id que le pusimos al crear la suscripcion
        # (pasa con los eventos de pago recurrente, PAYMENT.SALE.*, que
        # solo traen billing_agreement_id -- ver app/paypal.py). Se
        # busca por indice en vez de escanear toda la tabla.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_paypal_subscription_id "
            "ON clients (paypal_subscription_id) WHERE paypal_subscription_id IS NOT NULL"
        )


def create_client(license_key: str, org_name: str, expires_at_iso: str, notes: str = "") -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO clients (license_key, org_name, subscription_expires_at, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (license_key, org_name, expires_at_iso, notes, _now_iso()),
        )


def get_client(license_key: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM clients WHERE license_key = ?", (license_key,)).fetchone()


def get_client_by_paypal_subscription_id(subscription_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM clients WHERE paypal_subscription_id = ?", (subscription_id,)
        ).fetchone()


def list_clients() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM clients ORDER BY created_at DESC").fetchall()


def set_expiry(license_key: str, expires_at_iso: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE clients SET subscription_expires_at = ? WHERE license_key = ?",
            (expires_at_iso, license_key),
        )
        return cur.rowcount > 0


def set_paypal_subscription_id(license_key: str, subscription_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE clients SET paypal_subscription_id = ? WHERE license_key = ?",
            (subscription_id, license_key),
        )
        return cur.rowcount > 0


def append_note(license_key: str, line: str) -> None:
    """Agrega una linea al historial de notas de un cliente (pagos
    recibidos, eventos de PayPal procesados, etc) -- se acota a los
    ultimos 50 renglones para que la columna no crezca sin limite."""
    with get_conn() as conn:
        row = conn.execute("SELECT notes FROM clients WHERE license_key = ?", (license_key,)).fetchone()
        if row is None:
            return
        lines = [ln for ln in (row["notes"] or "").split("\n") if ln]
        lines.append(f"{_now_iso()} {line}")
        lines = lines[-50:]
        conn.execute(
            "UPDATE clients SET notes = ? WHERE license_key = ?", ("\n".join(lines), license_key)
        )
