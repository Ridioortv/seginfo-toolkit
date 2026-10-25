"""Registro auditable: encadenado, firma, deteccion de manipulacion y exportacion."""
import json

from sqlalchemy import delete, update

from app import ledger
from app.gov_models import LedgerEntry
from tests.gov_helpers import run_db

ORG = "org-1"


async def _fill(factory, n=5, org=ORG):
    async with factory() as db:
        for i in range(n):
            await ledger.append_entry(db, org, "change.recorded", "ana@acme.com", f"sha{i}", {"i": i, "origin": "ai"})
        await db.commit()


def test_chain_is_valid_and_numbered():
    async def go(factory):
        await _fill(factory, 5)
        async with factory() as db:
            result = await ledger.verify_chain(db, ORG)
            total, rows = await ledger.list_entries(db, ORG, limit=10)
            return result, total, rows
    result, total, rows = run_db(go)
    assert result["ok"] and result["entries"] == 5 and result["broken_at_seq"] is None
    assert total == 5 and [r.seq for r in rows] == [5, 4, 3, 2, 1]
    assert rows[-1].prev_hash == ledger.GENESIS_HASH and rows[0].prev_hash == rows[1].entry_hash


def test_each_organization_has_its_own_chain():
    async def go(factory):
        await _fill(factory, 3, "org-a")
        await _fill(factory, 2, "org-b")
        async with factory() as db:
            return await ledger.verify_chain(db, "org-a"), await ledger.verify_chain(db, "org-b")
    a, b = run_db(go)
    assert a["ok"] and a["entries"] == 3 and b["ok"] and b["entries"] == 2 and a["head_hash"] != b["head_hash"]


def test_editing_an_entry_is_detected():
    async def go(factory):
        await _fill(factory, 5)
        async with factory() as db:
            await db.execute(update(LedgerEntry).where(LedgerEntry.seq == 3).values(actor="otra-persona@acme.com"))
            await db.commit()
            return await ledger.verify_chain(db, ORG)
    result = run_db(go)
    assert not result["ok"] and result["broken_at_seq"] == 3 and "modificado" in result["reason"]


def test_deleting_a_middle_entry_is_detected():
    async def go(factory):
        await _fill(factory, 5)
        async with factory() as db:
            await db.execute(delete(LedgerEntry).where(LedgerEntry.seq == 2))
            await db.commit()
            return await ledger.verify_chain(db, ORG)
    result = run_db(go)
    assert not result["ok"] and result["broken_at_seq"] == 3


def test_recomputing_hashes_without_the_key_is_detected(monkeypatch):
    """Quien tenga la base pero no la clave puede rehacer los hashes, no las firmas."""
    async def go(factory):
        await _fill(factory, 4)
        async with factory() as db:
            rows = (await db.execute(LedgerEntry.__table__.select().order_by(LedgerEntry.seq))).all()
            prev = ledger.GENESIS_HASH
            for r in rows:
                payload = json.dumps({"i": "reescrito"}) if r.seq == 2 else r.payload
                h = ledger.compute_hash(ledger.canonical(ORG, r.seq, r.ts, r.event_type, r.actor, r.subject, payload, prev))
                await db.execute(update(LedgerEntry).where(LedgerEntry.seq == r.seq).values(payload=payload, prev_hash=prev, entry_hash=h))
                prev = h
            await db.commit()
            return await ledger.verify_chain(db, ORG)
    result = run_db(go)
    assert not result["ok"] and result["broken_at_seq"] == 2 and "firma" in result["reason"]


def test_deleting_the_tail_is_caught_with_an_external_anchor():
    async def go(factory):
        await _fill(factory, 5)
        async with factory() as db:
            anchor = await ledger.anchor(db, ORG)
            before = await ledger.verify_chain(db, ORG, anchor["entries"], anchor["head_hash"])
            await db.execute(delete(LedgerEntry).where(LedgerEntry.seq.in_([4, 5])))
            await db.commit()
            without_anchor = await ledger.verify_chain(db, ORG)
            with_anchor = await ledger.verify_chain(db, ORG, anchor["entries"], anchor["head_hash"])
            return anchor, before, without_anchor, with_anchor
    anchor, before, without_anchor, with_anchor = run_db(go)
    assert before["ok"] and before["anchor_checked"]
    assert without_anchor["ok"]  # sin ancla externa borrar el final no se puede detectar: por eso existe el ancla
    assert not with_anchor["ok"] and "ancla" in with_anchor["reason"]
    assert anchor["signature"] == ledger.anchor_signature(5, anchor["head_hash"], ORG)


def test_export_json_is_self_verifying_and_csv_is_formula_safe():
    async def go(factory):
        await _fill(factory, 3)
        async with factory() as db:
            await ledger.append_entry(db, ORG, "policy.created", "=HYPERLINK(\"http://x\")", "p1", {})
            await db.commit()
            return await ledger.export_json(db, ORG), await ledger.export_csv(db, ORG)
    exported, csv_text = run_db(go)
    assert exported["verification"]["ok"] and len(exported["entries"]) == 4
    prev = ledger.GENESIS_HASH
    for e in exported["entries"]:  # un auditor puede recalcular los hashes con solo el JSON
        payload = ledger.payload_text(e["payload"])
        assert e["prev_hash"] == prev
        assert ledger.compute_hash(ledger.canonical(ORG, e["seq"], e["ts"], e["event_type"], e["actor"], e["subject"], payload, e["prev_hash"])) == e["entry_hash"]
        prev = e["entry_hash"]
    assert "'=HYPERLINK" in csv_text and "\n=HYPERLINK" not in csv_text
