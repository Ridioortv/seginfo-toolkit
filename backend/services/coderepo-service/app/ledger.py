"""Registro de auditoria encadenado y firmado ("libro de procedencia").

Como evita la manipulacion:
  * Cada entrada incluye el hash de la anterior (prev_hash): editar o borrar una entrada del
    medio rompe el encadenado de todas las siguientes.
  * Cada hash se firma con HMAC-SHA256 usando una clave que NO esta en la base (AUDIT_LEDGER_KEY,
    o derivada de JWT_SECRET_KEY): quien solo tenga acceso a la base no puede recalcular una
    cadena valida.
  * El "ancla" (cantidad + hash de la ultima entrada, firmado) se puede guardar por fuera (un
    mail, un ticket, otro sistema): borrar las ultimas entradas ya no pasa desapercibido porque
    la verificacion contra el ancla falla.
El registro es por organizacion y solo se agrega (append-only): este modulo no tiene ninguna
funcion para modificar ni borrar entradas."""
import csv
import hashlib
import hmac
import io
import json
import os
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.security import JWT_SECRET_KEY
from app.gov_models import LedgerEntry

GENESIS_HASH = "0" * 64
LEDGER_VERSION = 1


def _signing_key() -> bytes:
    explicit = os.getenv("AUDIT_LEDGER_KEY", "").strip()
    if explicit:
        return explicit.encode()
    return hmac.new(JWT_SECRET_KEY.encode(), b"tero-governance-ledger-v1", hashlib.sha256).digest()


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical(org: str | None, seq: int, ts: str, event_type: str, actor: str, subject: str, payload: str, prev_hash: str) -> str:
    return json.dumps(
        {"v": LEDGER_VERSION, "org": org or "", "seq": seq, "ts": ts, "type": event_type,
         "actor": actor, "subject": subject, "payload": payload, "prev": prev_hash},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )


def compute_hash(canonical_text: str) -> str:
    return hashlib.sha256(canonical_text.encode()).hexdigest()


def sign(entry_hash: str) -> str:
    return hmac.new(_signing_key(), entry_hash.encode(), hashlib.sha256).hexdigest()


def anchor_signature(count: int, head_hash: str, org: str | None) -> str:
    return hmac.new(_signing_key(), f"anchor|{org or ''}|{count}|{head_hash}".encode(), hashlib.sha256).hexdigest()


def payload_text(payload: dict | None) -> str:
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


async def append_entry(
    db: AsyncSession, organization_id: str | None, event_type: str, actor: str, subject: str, payload: dict | None = None,
) -> LedgerEntry:
    """Agrega una entrada al final de la cadena de la organizacion (nunca modifica las existentes).
    La lectura de la ultima fila usa FOR UPDATE en Postgres para serializar escritores; ademas
    (organization_id, seq) es UNIQUE, asi que un choque de escritores falla en vez de bifurcar."""
    last = (await db.execute(
        select(LedgerEntry).where(LedgerEntry.organization_id == organization_id)
        .order_by(LedgerEntry.seq.desc()).limit(1).with_for_update()
    )).scalars().first()
    seq = (last.seq + 1) if last else 1
    prev_hash = last.entry_hash if last else GENESIS_HASH
    ts = now_ts()
    body = payload_text(payload)
    actor = (actor or "")[:255]
    subject = (subject or "")[:255]
    entry_hash = compute_hash(canonical(organization_id, seq, ts, event_type, actor, subject, body, prev_hash))
    entry = LedgerEntry(
        organization_id=organization_id, seq=seq, ts=ts, event_type=event_type, actor=actor, subject=subject,
        payload=body, prev_hash=prev_hash, entry_hash=entry_hash, signature=sign(entry_hash),
    )
    db.add(entry)
    await db.flush()
    return entry


async def _all_entries(db: AsyncSession, organization_id: str | None) -> list[LedgerEntry]:
    result = await db.execute(
        select(LedgerEntry).where(LedgerEntry.organization_id == organization_id).order_by(LedgerEntry.seq.asc())
    )
    return list(result.scalars().all())


def verify_entries(entries: list[LedgerEntry], organization_id: str | None) -> dict:
    """Recalcula toda la cadena. Devuelve el primer punto roto (si lo hay) y por que."""
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for e in entries:
        if e.seq != expected_seq:
            return _broken(entries, e.seq, "falta una o mas entradas (secuencia interrumpida)")
        if e.prev_hash != expected_prev:
            return _broken(entries, e.seq, "el encadenado no coincide con la entrada anterior")
        recomputed = compute_hash(canonical(organization_id, e.seq, e.ts, e.event_type, e.actor, e.subject, e.payload, e.prev_hash))
        if not hmac.compare_digest(recomputed, e.entry_hash):
            return _broken(entries, e.seq, "el contenido de la entrada fue modificado")
        if not hmac.compare_digest(sign(e.entry_hash), e.signature):
            return _broken(entries, e.seq, "la firma no es valida (no la genero este sistema)")
        expected_prev = e.entry_hash
        expected_seq += 1
    return {
        "ok": True, "entries": len(entries), "head_hash": expected_prev if entries else GENESIS_HASH,
        "broken_at_seq": None, "reason": "",
    }


def _broken(entries: list[LedgerEntry], seq: int, reason: str) -> dict:
    return {"ok": False, "entries": len(entries), "head_hash": entries[-1].entry_hash if entries else GENESIS_HASH,
            "broken_at_seq": seq, "reason": reason}


async def verify_chain(db: AsyncSession, organization_id: str | None, expected_count: int | None = None,
                       expected_head: str | None = None) -> dict:
    """Verifica la cadena. Si se pasa un ancla externa (cantidad y/o hash final guardados antes),
    tambien detecta que se hayan borrado entradas del final."""
    entries = await _all_entries(db, organization_id)
    result = verify_entries(entries, organization_id)
    result["anchor_checked"] = False
    if result["ok"] and (expected_count is not None or expected_head):
        result["anchor_checked"] = True
        if expected_count is not None and result["entries"] != expected_count:
            result.update(ok=False, reason=f"el ancla dice {expected_count} entradas y hay {result['entries']}")
        elif expected_head and result["head_hash"] != expected_head:
            result.update(ok=False, reason="el hash final no coincide con el ancla guardada")
    return result


async def anchor(db: AsyncSession, organization_id: str | None) -> dict:
    entries = await _all_entries(db, organization_id)
    head = entries[-1].entry_hash if entries else GENESIS_HASH
    return {
        "entries": len(entries), "head_hash": head, "generated_at": now_ts(),
        "signature": anchor_signature(len(entries), head, organization_id),
    }


async def head(db: AsyncSession, organization_id: str | None) -> dict:
    """Cantidad de entradas y hash de la ultima (liviano: no recorre toda la cadena)."""
    count = (await db.execute(
        select(func.count()).select_from(LedgerEntry).where(LedgerEntry.organization_id == organization_id))).scalar_one()
    last = (await db.execute(
        select(LedgerEntry).where(LedgerEntry.organization_id == organization_id)
        .order_by(LedgerEntry.seq.desc()).limit(1))).scalars().first()
    return {"entries": count, "head_hash": last.entry_hash if last else GENESIS_HASH}


async def list_entries(db: AsyncSession, organization_id: str | None, limit: int = 100, offset: int = 0,
                       event_type: str | None = None) -> tuple[int, list[LedgerEntry]]:
    q = select(LedgerEntry).where(LedgerEntry.organization_id == organization_id)
    count_q = select(func.count()).select_from(LedgerEntry).where(LedgerEntry.organization_id == organization_id)
    if event_type:
        q = q.where(LedgerEntry.event_type == event_type)
        count_q = count_q.where(LedgerEntry.event_type == event_type)
    total = (await db.execute(count_q)).scalar_one()
    rows = (await db.execute(q.order_by(LedgerEntry.seq.desc()).limit(limit).offset(offset))).scalars().all()
    return total, list(rows)


def entry_to_dict(e: LedgerEntry) -> dict:
    try:
        payload = json.loads(e.payload)
    except ValueError:
        payload = {"_raw": e.payload}
    return {
        "seq": e.seq, "ts": e.ts, "event_type": e.event_type, "actor": e.actor, "subject": e.subject,
        "payload": payload, "prev_hash": e.prev_hash, "entry_hash": e.entry_hash, "signature": e.signature,
    }


async def export_json(db: AsyncSession, organization_id: str | None) -> dict:
    entries = await _all_entries(db, organization_id)
    verification = verify_entries(entries, organization_id)
    return {
        "format": "tero-governance-ledger", "version": LEDGER_VERSION, "organization_id": organization_id,
        "exported_at": now_ts(), "verification": verification,
        "anchor": {"entries": len(entries), "head_hash": verification["head_hash"],
                   "signature": anchor_signature(len(entries), verification["head_hash"], organization_id)},
        "how_to_verify": (
            "Cada entry_hash es SHA-256 del JSON canonico (claves ordenadas, sin espacios) con los campos "
            "v, org, seq, ts, type, actor, subject, payload y prev. prev debe ser el entry_hash de la entrada "
            "anterior (la primera usa 64 ceros). signature es HMAC-SHA256 del entry_hash con la clave de la "
            "instalacion."
        ),
        "entries": [entry_to_dict(e) for e in entries],
    }


async def export_csv(db: AsyncSession, organization_id: str | None) -> str:
    entries = await _all_entries(db, organization_id)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["seq", "ts", "event_type", "actor", "subject", "payload", "prev_hash", "entry_hash", "signature"])
    for e in entries:
        writer.writerow([e.seq, e.ts, e.event_type, _csv_safe(e.actor), _csv_safe(e.subject), _csv_safe(e.payload),
                         e.prev_hash, e.entry_hash, e.signature])
    return out.getvalue()


def _csv_safe(value: str) -> str:
    """Evita la inyeccion de formulas al abrir el CSV en Excel/Sheets."""
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value
