"""Logica de la cadena de custodia: agregar eventos, verificar, firmar el ancla y armar el
"paquete de evidencia" de un caso (ver backend/shared/custody_core.py para el diseno criptografico)."""
import csv
import io
import json
import zipfile
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from app.custody_models import CustodyEntry

VERIFIER_PATH = Path(__file__).resolve().parent / "assets" / "verificar_evidencia.py"

# Eventos que solo puede escribir case-service (los de otros servicios llegan por /internal/custody/events).
RESERVED_PREFIXES = ("case.", "evidence.")
EXTERNAL_PREFIXES = ("alert.", "soar.", "vuln.", "scan.", "asset.", "sovereignty.", "drill.", "compliance.", "gov.")


class CustodyError(Exception):
    pass


async def append(
    db: AsyncSession, organization_id: str | None, event_type: str, actor: str = "", source: str = "",
    subject_type: str = "", subject_id: str = "", refs=None, payload: dict | None = None,
) -> CustodyEntry:
    """Agrega una entrada al final de la cadena de la organizacion. (organization_id, seq) es UNIQUE:
    si dos escritores chocan, el segundo reintenta con el seq siguiente en vez de bifurcar la cadena."""
    body = core.payload_text(payload)
    if len(body.encode("utf-8")) > core.MAX_PAYLOAD_BYTES:
        raise CustodyError("el detalle del evento es demasiado grande")
    actor, source = (actor or "")[:255], (source or "")[:50]
    subject_type, subject_id = (subject_type or "")[:30], (subject_id or "")[:100]
    ref_list = core.normalize_refs(refs)
    payload_sha = core.sha256_hex(body)
    leaf = core.leaf_hash(core.leaf_fields(event_type, actor, source, subject_type, subject_id, ref_list, payload_sha))

    last_error: Exception | None = None
    for _ in range(5):
        try:
            async with db.begin_nested():
                last = (await db.execute(
                    select(CustodyEntry).where(CustodyEntry.organization_id == organization_id)
                    .order_by(CustodyEntry.seq.desc()).limit(1).with_for_update()
                )).scalars().first()
                seq = (last.seq + 1) if last else 1
                prev = last.entry_hash if last else core.GENESIS_HASH
                ts = core.now_ts()
                entry_hash = core.entry_hash(organization_id, seq, ts, prev, leaf)
                entry = CustodyEntry(
                    organization_id=organization_id, seq=seq, ts=ts, event_type=event_type, actor=actor,
                    source=source, subject_type=subject_type, subject_id=subject_id,
                    refs=core.canonical(ref_list), payload=body, payload_sha256=payload_sha, leaf=leaf,
                    prev_hash=prev, entry_hash=entry_hash, signature=core.sign_hex(entry_hash),
                )
                db.add(entry)
                await db.flush()
            return entry
        except IntegrityError as exc:
            last_error = exc
    raise CustodyError(f"no se pudo agregar a la cadena de custodia: {last_error}")


async def all_entries(db: AsyncSession, organization_id: str | None) -> list[CustodyEntry]:
    result = await db.execute(
        select(CustodyEntry).where(CustodyEntry.organization_id == organization_id).order_by(CustodyEntry.seq.asc()))
    return list(result.scalars().all())


def _row(e: CustodyEntry) -> dict:
    return {"seq": e.seq, "ts": e.ts, "prev": e.prev_hash, "leaf": e.leaf, "entry_hash": e.entry_hash,
            "signature": e.signature}


def _fields(e: CustodyEntry) -> dict:
    return core.leaf_fields(e.event_type, e.actor, e.source, e.subject_type, e.subject_id,
                            json.loads(e.refs or "[]"), e.payload_sha256)


def verify_rows(entries: list[CustodyEntry], organization_id: str | None) -> dict:
    """Verifica el encadenado y las firmas, y que el contenido guardado de cada entrada siga siendo el firmado."""
    pub = core.public_key_hex()
    rows = [_row(e) for e in entries]
    result = core.verify_chain_rows(rows, organization_id, pub)
    if not result["ok"]:
        return result
    for e in entries:
        if core.leaf_hash(_fields(e)) != e.leaf:
            return core._broken(rows, e.seq, "el contenido de la entrada fue modificado")
        if core.sha256_hex(e.payload) != e.payload_sha256:
            return core._broken(rows, e.seq, "el detalle del evento fue modificado")
    return result


async def verify(db: AsyncSession, organization_id: str | None, expected_count: int | None = None,
                 expected_head: str | None = None) -> dict:
    entries = await all_entries(db, organization_id)
    result = verify_rows(entries, organization_id)
    result["anchor_checked"] = False
    if result["ok"] and (expected_count is not None or expected_head):
        result["anchor_checked"] = True
        if expected_count is not None and result["entries"] != expected_count:
            result.update(ok=False, reason=f"el ancla dice {expected_count} entradas y hay {result['entries']}")
        elif expected_head and result["head_hash"] != expected_head:
            result.update(ok=False, reason="el hash final no coincide con el ancla guardada")
    return result


def make_anchor(organization_id: str | None, count: int, head_hash: str) -> dict:
    generated_at = core.now_ts()
    return {"entries": count, "head_hash": head_hash, "generated_at": generated_at,
            "signature": core.sign_bytes(core.anchor_message(organization_id, count, head_hash, generated_at))}


async def anchor(db: AsyncSession, organization_id: str | None) -> dict:
    entries = await all_entries(db, organization_id)
    head = entries[-1].entry_hash if entries else core.GENESIS_HASH
    return make_anchor(organization_id, len(entries), head)


async def head(db: AsyncSession, organization_id: str | None) -> dict:
    count = (await db.execute(
        select(func.count()).select_from(CustodyEntry).where(CustodyEntry.organization_id == organization_id))).scalar_one()
    last = (await db.execute(
        select(CustodyEntry).where(CustodyEntry.organization_id == organization_id)
        .order_by(CustodyEntry.seq.desc()).limit(1))).scalars().first()
    return {"entries": count, "head_hash": last.entry_hash if last else core.GENESIS_HASH}


async def list_entries(db: AsyncSession, organization_id: str | None, limit: int = 100, offset: int = 0,
                       event_type: str | None = None, subject_id: str | None = None) -> tuple[int, list[CustodyEntry]]:
    q = select(CustodyEntry).where(CustodyEntry.organization_id == organization_id)
    cq = select(func.count()).select_from(CustodyEntry).where(CustodyEntry.organization_id == organization_id)
    if event_type:
        q, cq = q.where(CustodyEntry.event_type == event_type), cq.where(CustodyEntry.event_type == event_type)
    if subject_id:
        q, cq = q.where(CustodyEntry.subject_id == subject_id), cq.where(CustodyEntry.subject_id == subject_id)
    total = (await db.execute(cq)).scalar_one()
    rows = (await db.execute(q.order_by(CustodyEntry.seq.desc()).limit(limit).offset(offset))).scalars().all()
    return total, list(rows)


def entry_to_dict(e: CustodyEntry) -> dict:
    try:
        payload = json.loads(e.payload)
    except ValueError:
        payload = {"_raw": e.payload}
    return {
        "seq": e.seq, "ts": e.ts, "event_type": e.event_type, "actor": e.actor, "source": e.source,
        "subject_type": e.subject_type, "subject_id": e.subject_id, "refs": json.loads(e.refs or "[]"),
        "payload": payload, "prev_hash": e.prev_hash, "entry_hash": e.entry_hash, "signature": e.signature,
    }


# --- Eventos de casos (los escribe case-service en la misma transaccion que el cambio) ---------------

def case_refs(case) -> list[str]:
    refs = [f"case:{case.id}"]
    if case.alert_id:
        refs.append(f"alert:{case.alert_id}")
    return refs


def case_state(case) -> dict:
    return {
        "title": case.title, "priority": getattr(case.priority, "value", case.priority),
        "status": getattr(case.status, "value", case.status), "assignee": case.assignee,
        "alert_id": case.alert_id, "source": case.source,
    }


async def record_case_event(db: AsyncSession, case, event_type: str, actor: str, extra: dict | None = None) -> CustodyEntry:
    payload = {"case": case_state(case), **(extra or {})}
    return await append(db, case.organization_id, event_type, actor=actor, source="case-service",
                        subject_type="case", subject_id=case.id, refs=case_refs(case), payload=payload)


# --- Paquete de evidencia ------------------------------------------------------------------------------

def case_snapshot(case) -> dict:
    def iso(value):
        return value.isoformat() if value is not None else None

    return {
        "id": case.id, "title": case.title, "description": case.description,
        "priority": getattr(case.priority, "value", case.priority),
        "status": getattr(case.status, "value", case.status), "assignee": case.assignee,
        "alert_id": case.alert_id, "source": case.source, "sla_due_at": iso(case.sla_due_at),
        "created_at": iso(case.created_at), "updated_at": iso(case.updated_at), "resolved_at": iso(case.resolved_at),
        "timeline": [
            {"actor": t.actor, "action": t.action, "notes": t.notes, "created_at": iso(t.created_at)}
            for t in sorted(case.timeline, key=lambda x: (x.created_at, x.id))
        ],
    }


README_TEXT = """PAQUETE DE EVIDENCIA - TERO Security
=====================================
Caso: {case_id}  ({title})
Generado: {generated_at}
Huella de la clave publica: {fingerprint}

Que contiene
  manifest.json            Ficha del caso, cadena de custodia firmada y ancla.
  entries.csv              Los eventos de este caso en formato legible (para abrir en Excel).
  verificar_evidencia.py   Programa de verificacion independiente (solo necesita Python 3.8+).

Como verificarlo (no hace falta TERO ni ningun secreto)
  1. Instalar Python 3 (python.org).
  2. Ejecutar:   python verificar_evidencia.py evidencia.zip
  3. Todos los controles deben dar [OK] y el resultado final EVIDENCIA INTEGRA.
  4. Confirmar que la huella de la clave publica coincide con la que muestra la instalacion de
     TERO que corresponde (pantalla "Cadena de custodia") o con la que informo el emisor por otro
     canal. Tambien se puede pasar:  --huella {fingerprint}

Que prueba y que no
  - Prueba que los eventos y la ficha del caso no se modificaron desde que se firmaron, y que no
    se quitaron ni reordenaron eventos de la cadena.
  - No prueba que los hechos registrados sean verdaderos: prueba lo que el sistema registro y cuando.
  - {key_note}
  - La cadena completa de la organizacion se incluye solo con sus huellas (sin contenido): del
    resto de los eventos no se revela nada, pero se puede comprobar que la cadena esta entera.
  - La validez legal como prueba depende de cada jurisdiccion y proceso: consultar con un abogado.
"""


def _csv_safe(value: str) -> str:
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


async def build_evidence_package(db: AsyncSession, case, actor: str) -> tuple[bytes, dict]:
    org = case.organization_id
    snapshot = case_snapshot(case)
    snapshot_sha = core.sha256_hex(core.canonical(snapshot))
    export_entry = await append(
        db, org, "evidence.exported", actor=actor, source="case-service", subject_type="case", subject_id=case.id,
        refs=case_refs(case), payload={"snapshot_sha256": snapshot_sha, "case_id": case.id},
    )
    entries = await all_entries(db, org)
    wanted = set(case_refs(case))

    def related(e: CustodyEntry) -> bool:
        return bool(wanted & set(json.loads(e.refs or "[]"))) or (e.subject_type == "case" and e.subject_id == case.id)

    chain, disclosed = [], []
    for e in entries:
        row = _row(e)
        if related(e):
            row["fields"] = _fields(e)
            row["payload"] = e.payload
            disclosed.append(e)
        chain.append(row)

    pub = core.public_key_hex()
    head_hash = entries[-1].entry_hash
    manifest = {
        "format": "tero-evidence-package", "version": 1, "organization_id": org or "",
        "generated_at": core.now_ts(), "case": snapshot, "snapshot_sha256": snapshot_sha,
        "public_key": pub, "key_fingerprint": core.key_fingerprint(pub),
        "key_derived_from_jwt": core.key_is_derived_from_jwt(),
        "export_seq": export_entry.seq, "chain": chain,
        "anchor": make_anchor(org, len(entries), head_hash),
    }
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(["seq", "fecha_utc", "tipo", "actor", "servicio", "sujeto", "detalle", "hash_entrada"])
    for e in disclosed:
        writer.writerow([e.seq, e.ts, e.event_type, _csv_safe(e.actor), e.source,
                         _csv_safe(f"{e.subject_type}:{e.subject_id}"), _csv_safe(e.payload), e.entry_hash])
    key_note = ("La clave de firma de esta instalacion se deriva del secreto JWT del servidor (no hay "
                "CUSTODY_SIGNING_SEED propio): quien administre el servidor podria rehacer la cadena entera."
                if manifest["key_derived_from_jwt"] else
                "La clave de firma de esta instalacion es propia (CUSTODY_SIGNING_SEED).")
    readme = README_TEXT.format(case_id=case.id, title=case.title, generated_at=manifest["generated_at"],
                                fingerprint=manifest["key_fingerprint"], key_note=key_note)

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        zf.writestr("entries.csv", csv_buf.getvalue())
        zf.writestr("LEEME.txt", readme)
        zf.writestr("verificar_evidencia.py", VERIFIER_PATH.read_text(encoding="utf-8"))
    return out.getvalue(), manifest
