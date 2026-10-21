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
                mp_preapproval_id TEXT
            )
            """
        )
        # Tiene que correr ANTES de crear los indices de mas abajo (si
        # la columna no existe todavia, CREATE INDEX sobre ella falla).
        _add_column_if_missing(cur, "clients", "paypal_subscription_id", "TEXT")
        _add_column_if_missing(cur, "clients", "mp_preapproval_id", "TEXT")

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
        # Igual que arriba pero para Mercado Pago: los avisos de cobro
        # (subscription_authorized_payment) traen el id de la suscripcion
        # (preapproval), no la license_key.
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_mp_preapproval_id "
            "ON clients (mp_preapproval_id) WHERE mp_preapproval_id IS NOT NULL"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS processed_events ("
            "event_id TEXT PRIMARY KEY, processed_at TEXT NOT NULL)"
        )
        # TODAS las suscripciones que se crearon para una licencia (no solo la
        # ultima, que es lo unico que guardan las columnas de `clients`). Sin
        # esto, un link viejo seguia siendo pagable y una segunda suscripcion
        # quedaba cobrando todos los meses sin que nadie la viera ni pudiera
        # cancelarla. status: pending (link creado, sin pagar), active (la que
        # cobra y extiende la licencia), cancelled, duplicate (se aprobo estando
        # ya activa otra: se cancela sola y sus cobros no extienden nada).
        cur.execute(
            "CREATE TABLE IF NOT EXISTS subscriptions ("
            "gateway TEXT NOT NULL, external_id TEXT NOT NULL, license_key TEXT NOT NULL, "
            "status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "PRIMARY KEY (gateway, external_id))"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_license ON subscriptions (license_key)")
        # Bases anteriores a esta tabla: se registran las suscripciones que ya
        # figuraban en `clients` (como pending; el estado real se consulta a la
        # pasarela cuando hace falta).
        now = _now_iso()
        cur.execute(
            _adapt(
                "INSERT INTO subscriptions (gateway, external_id, license_key, status, created_at, updated_at) "
                "SELECT 'paypal', paypal_subscription_id, license_key, 'pending', ?, ? FROM clients "
                "WHERE paypal_subscription_id IS NOT NULL ON CONFLICT (gateway, external_id) DO NOTHING"
            ),
            (now, now),
        )
        cur.execute(
            _adapt(
                "INSERT INTO subscriptions (gateway, external_id, license_key, status, created_at, updated_at) "
                "SELECT 'mercadopago', mp_preapproval_id, license_key, 'pending', ?, ? FROM clients "
                "WHERE mp_preapproval_id IS NOT NULL ON CONFLICT (gateway, external_id) DO NOTHING"
            ),
            (now, now),
        )


def claim_event(event_id: str) -> bool:
    """Idempotencia de webhooks: PayPal reintenta un webhook si no recibe
    2xx a tiempo, y sin esto cada reintento extenderia la licencia otros 30
    dias. Devuelve True la PRIMERA vez que se ve este event_id (hay que
    procesarlo) y False si ya se habia procesado (hay que ignorarlo)."""
    with get_cursor() as cur:
        cur.execute(
            _adapt(
                "INSERT INTO processed_events (event_id, processed_at) VALUES (?, ?) "
                "ON CONFLICT (event_id) DO NOTHING"
            ),
            (event_id, _now_iso()),
        )
        return cur.rowcount > 0


def release_event(event_id: str) -> None:
    """Deshace claim_event: el evento NO se pudo aplicar (cliente sin resolver,
    error transitorio), asi que el reintento de PayPal tiene que poder
    procesarlo en vez de ser descartado como duplicado."""
    with get_cursor() as cur:
        cur.execute(_adapt("DELETE FROM processed_events WHERE event_id = ?"), (event_id,))


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


def get_client_by_mp_preapproval_id(preapproval_id: str):
    with get_cursor() as cur:
        cur.execute(_adapt("SELECT * FROM clients WHERE mp_preapproval_id = ?"), (preapproval_id,))
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


def _insert_subscription(cur, license_key: str, gateway: str, external_id: str, status: str) -> None:
    now = _now_iso()
    cur.execute(
        _adapt(
            "INSERT INTO subscriptions (gateway, external_id, license_key, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (gateway, external_id) DO NOTHING"
        ),
        (gateway, external_id, license_key, status, now, now),
    )


def set_paypal_subscription_id(license_key: str, subscription_id: str) -> bool:
    """Guarda la ULTIMA suscripcion de PayPal en `clients` (compatibilidad) y la
    registra en `subscriptions` junto con todas las anteriores."""
    with get_cursor() as cur:
        cur.execute(
            _adapt("UPDATE clients SET paypal_subscription_id = ? WHERE license_key = ?"),
            (subscription_id, license_key),
        )
        found = cur.rowcount > 0
        if found:
            _insert_subscription(cur, license_key, "paypal", subscription_id, "pending")
        return found


def set_mp_preapproval_id(license_key: str, preapproval_id: str) -> bool:
    """Idem set_paypal_subscription_id, para Mercado Pago."""
    with get_cursor() as cur:
        cur.execute(
            _adapt("UPDATE clients SET mp_preapproval_id = ? WHERE license_key = ?"),
            (preapproval_id, license_key),
        )
        found = cur.rowcount > 0
        if found:
            _insert_subscription(cur, license_key, "mercadopago", preapproval_id, "pending")
        return found


def add_subscription(license_key: str, gateway: str, external_id: str, status: str = "pending") -> None:
    with get_cursor() as cur:
        _insert_subscription(cur, license_key, gateway, external_id, status)


def get_subscription(gateway: str, external_id: str):
    with get_cursor() as cur:
        cur.execute(
            _adapt("SELECT * FROM subscriptions WHERE gateway = ? AND external_id = ?"), (gateway, external_id)
        )
        return cur.fetchone()


def list_subscriptions(license_key: str, statuses: tuple[str, ...] | None = None, gateway: str | None = None) -> list:
    """Suscripciones de una licencia, la mas vieja primero. `statuses` / `gateway`
    filtran (None = todas)."""
    sql = "SELECT * FROM subscriptions WHERE license_key = ?"
    params: list = [license_key]
    if statuses:
        sql += " AND status IN (" + ", ".join("?" for _ in statuses) + ")"
        params.extend(statuses)
    if gateway:
        sql += " AND gateway = ?"
        params.append(gateway)
    sql += " ORDER BY created_at, external_id"
    with get_cursor() as cur:
        cur.execute(_adapt(sql), tuple(params))
        return cur.fetchall()


def set_subscription_status(gateway: str, external_id: str, status: str) -> bool:
    """Cambia el estado local. Una suscripcion marcada `duplicate` no vuelve a
    otro estado (el aviso de cancelacion que manda la pasarela despues de que la
    cancelamos nosotros no debe taparlo)."""
    sql = "UPDATE subscriptions SET status = ?, updated_at = ? WHERE gateway = ? AND external_id = ?"
    if status != "duplicate":
        sql += " AND status <> 'duplicate'"
    with get_cursor() as cur:
        cur.execute(_adapt(sql), (status, _now_iso(), gateway, external_id))
        return cur.rowcount > 0


def claim_active_subscription(license_key: str, gateway: str, external_id: str) -> bool:
    """Reclama, de forma atomica, el lugar de "la suscripcion activa" de la
    licencia: True si esta suscripcion queda activa (o ya lo estaba); False si
    otra distinta ya esta activa o si esta fue marcada duplicate. Es lo que
    evita que dos suscripciones aprobadas a la vez extiendan la licencia las dos."""
    with get_cursor() as cur:
        cur.execute(
            _adapt(
                "UPDATE subscriptions SET status = 'active', updated_at = ? "
                "WHERE gateway = ? AND external_id = ? AND license_key = ? AND status <> 'duplicate' "
                "AND NOT EXISTS (SELECT 1 FROM subscriptions o WHERE o.license_key = ? AND o.status = 'active' "
                "AND NOT (o.gateway = ? AND o.external_id = ?))"
            ),
            (_now_iso(), gateway, external_id, license_key, license_key, gateway, external_id),
        )
        return cur.rowcount > 0


def append_note(license_key: str, line: str) -> None:
    """Agrega una linea al historial de notas de un cliente (pagos
    recibidos, eventos de PayPal procesados, etc) -- se
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
