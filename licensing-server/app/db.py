"""Almacenamiento de este servidor -- dos backends posibles, elegidos
por variable de entorno:

- SQLite (default, sin DATABASE_URL seteado): el archivo vive en un
  volumen local -- pensado para un VPS propio con Docker Compose
  (ver docker-compose.yml), donde el disco es persistente entre
  reinicios.
- Postgres (si DATABASE_URL esta seteado, ej. la connection string que
  da Neon/Supabase gratis): pensado para desplegar en una plataforma
  tipo Render, cuyo plan gratis NO tiene disco persistente -- ahi
  SQLite se borraria en cada reinicio/redeploy, asi que la base tiene
  que vivir afuera del contenedor.

El trafico esperado es minimo (unos pocos clientes haciendo check-in
una o dos veces por dia, mas los pocos requests admin que hace el
operador a mano) -- ninguno de los dos backends necesita nada mas
sofisticado que esto. Todo el SQL de este archivo esta escrito en la
sintaxis de SQLite (placeholders "?") y se traduce a "%s" al ejecutar
si DATABASE_URL esta seteado (ver _adapt) -- evita mantener dos copias
de cada query. FastAPI corre las rutas `def` (sync, no `async def`) en
un threadpool, asi que ninguno de los dos bloquea el event loop."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

DATABASE_URL = os.getenv("DATABASE_URL", "")
DB_PATH = os.getenv("LICENSING_DB_PATH", "./licensing.db")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _adapt(sql: str) -> str:
    """Unica diferencia de sintaxis entre los dos backends para las
    queries de este archivo: el placeholder de parametros. Ninguna
    query de aca tiene un "?" literal fuera de un placeholder, asi que
    el reemplazo es seguro."""
    return sql.replace("?", "%s") if DATABASE_URL else sql


@contextmanager
def get_cursor():
    """Yieldea un cursor (no la conexion): asi el resto del archivo no
    necesita saber cual de los dos backends esta activo -- ambos
    cursores soportan .execute()/.fetchone()/.fetchall() con filas
    accesibles por nombre de columna (sqlite3.Row / RealDictCursor)."""
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    finally:
        conn.close()


def _add_column_if_missing(cur, table: str, column: str, coltype: str) -> None:
    """Para bases creadas antes de que existiera esta columna --
    CREATE TABLE IF NOT EXISTS no la agrega sola si la tabla ya
    existia de una version anterior de este archivo. Postgres soporta
    "ADD COLUMN IF NOT EXISTS" nativo; SQLite no, asi que ahi se
    intenta y se ignora el error si ya existe (importante NO usar
    try/except tambien del lado Postgres: un ALTER que falla ahi deja
    la transaccion entera "abortada" hasta el proximo rollback, y
    rompe cualquier statement que venga despues en el mismo bloque)."""
    if DATABASE_URL:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {coltype}")
    else:
        try:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
        except sqlite3.OperationalError:
            pass


def init_db() -> None:
    with get_cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                license_key TEXT PRIMARY KEY,
                org_name TEXT NOT NULL,
                subscription_expires_at TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                paypal_subscription_id TEXT,
                mercadopago_preapproval_id TEXT
            )
            """
        )
        # Tiene que correr ANTES de crear los indices de mas abajo (si
        # la columna no existe todavia, CREATE INDEX sobre ella falla).
        _add_column_if_missing(cur, "clients", "paypal_subscription_id", "TEXT")
        _add_column_if_missing(cur, "clients", "mercadopago_preapproval_id", "TEXT")

        # paypal_subscription_id se usa para encontrar que cliente
        # corresponde a un webhook de PayPal cuyo evento no trae de
        # vuelta el custom_id que le pusimos al crear la suscripcion
        # (pasa con los eventos de pago recurrente, PAYMENT.SALE.*, que
        # solo traen billing_agreement_id -- ver app/paypal.py). Se
        # busca por indice en vez de escanear toda la tabla. Los
        # indices parciales (WHERE ... IS NOT NULL) funcionan igual en
        # los dos backends.
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_paypal_subscription_id "
            "ON clients (paypal_subscription_id) WHERE paypal_subscription_id IS NOT NULL"
        )
        # Idem para Mercado Pago -- respaldo para cuando un
        # authorized_payment no trae external_reference (ver
        # app/mercadopago.py::resolve_license_key_lookup).
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_mercadopago_preapproval_id "
            "ON clients (mercadopago_preapproval_id) WHERE mercadopago_preapproval_id IS NOT NULL"
        )


def create_client(license_key: str, org_name: str, expires_at_iso: str, notes: str = "") -> None:
    with get_cursor() as cur:
        cur.execute(
            _adapt(
                "INSERT INTO clients (license_key, org_name, subscription_expires_at, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?)"
            ),
            (license_key, org_name, expires_at_iso, notes, _now_iso()),
        )


def get_client(license_key: str):
    with get_cursor() as cur:
        cur.execute(_adapt("SELECT * FROM clients WHERE license_key = ?"), (license_key,))
        return cur.fetchone()


def get_client_by_paypal_subscription_id(subscription_id: str):
    with get_cursor() as cur:
        cur.execute(
            _adapt("SELECT * FROM clients WHERE paypal_subscription_id = ?"), (subscription_id,)
        )
        return cur.fetchone()


def list_clients() -> list:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM clients ORDER BY created_at DESC")
        return cur.fetchall()


def set_expiry(license_key: str, expires_at_iso: str) -> bool:
    with get_cursor() as cur:
        cur.execute(
            _adapt("UPDATE clients SET subscription_expires_at = ? WHERE license_key = ?"),
            (expires_at_iso, license_key),
        )
        return cur.rowcount > 0


def set_paypal_subscription_id(license_key: str, subscription_id: str) -> bool:
    with get_cursor() as cur:
        cur.execute(
            _adapt("UPDATE clients SET paypal_subscription_id = ? WHERE license_key = ?"),
            (subscription_id, license_key),
        )
        return cur.rowcount > 0


def get_client_by_mercadopago_preapproval_id(preapproval_id: str):
    with get_cursor() as cur:
        cur.execute(
            _adapt("SELECT * FROM clients WHERE mercadopago_preapproval_id = ?"), (preapproval_id,)
        )
        return cur.fetchone()


def set_mercadopago_preapproval_id(license_key: str, preapproval_id: str) -> bool:
    with get_cursor() as cur:
        cur.execute(
            _adapt("UPDATE clients SET mercadopago_preapproval_id = ? WHERE license_key = ?"),
            (preapproval_id, license_key),
        )
        return cur.rowcount > 0


def append_note(license_key: str, line: str) -> None:
    """Agrega una linea al historial de notas de un cliente (pagos
    recibidos, eventos de PayPal/Mercado Pago procesados, etc) -- se
    acota a los ultimos 50 renglones para que la columna no crezca sin
    limite."""
    with get_cursor() as cur:
        cur.execute(_adapt("SELECT notes FROM clients WHERE license_key = ?"), (license_key,))
        row = cur.fetchone()
        if row is None:
            return
        lines = [ln for ln in (row["notes"] or "").split("\n") if ln]
        lines.append(f"{_now_iso()} {line}")
        lines = lines[-50:]
        cur.execute(
            _adapt("UPDATE clients SET notes = ? WHERE license_key = ?"),
            ("\n".join(lines), license_key),
        )
