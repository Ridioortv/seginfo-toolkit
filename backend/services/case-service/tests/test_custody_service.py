"""Servicio de custodia con SQLite: agregar, verificar, anclar, manipular la base y paquete de evidencia."""
import json
import zipfile
import io
import asyncio
import datetime as dt

import pytest
from sqlalchemy import update, delete

from app import custody_service as custody
from app.custody_models import CustodyEntry
from app.models import Case, CasePriority, CaseStatus
from backend.shared import custody_core as core
from custody_helpers import run_db

ORG = "org-1"


@pytest.fixture(autouse=True)
def seed(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")


async def seed_chain(factory, n=4):
    async with factory() as db:
        for i in range(n):
            await custody.append(db, ORG, "scan.completed", actor="sys", source="scan-service",
                                 subject_type="scan", subject_id=f"s{i}", refs=[f"asset:a{i % 2}"], payload={"n": i})
        await db.commit()


def test_append_builds_a_verifiable_chain():
    async def go(factory):
        await seed_chain(factory)
        async with factory() as db:
            res = await custody.verify(db, ORG)
            assert res["ok"] and res["entries"] == 4
            assert (await custody.head(db, ORG))["head_hash"] == res["head_hash"]
            # otra organizacion tiene su propia cadena, desde el genesis
            e = await custody.append(db, "org-2", "scan.completed", payload={})
            assert e.seq == 1 and e.prev_hash == core.GENESIS_HASH
    run_db(go)


def test_payload_too_large_is_refused():
    async def go(factory):
        async with factory() as db:
            with pytest.raises(custody.CustodyError):
                await custody.append(db, ORG, "scan.completed", payload={"x": "a" * (core.MAX_PAYLOAD_BYTES + 1)})
    run_db(go)


@pytest.mark.parametrize("tamper", ["payload", "actor", "delete_middle", "delete_tail", "forge_signature"])
def test_database_tampering_is_detected(tamper):
    async def go(factory):
        await seed_chain(factory)
        async with factory() as db:
            anchor = await custody.anchor(db, ORG)
            if tamper == "payload":
                await db.execute(update(CustodyEntry).where(CustodyEntry.seq == 2).values(payload='{"n":999}'))
            elif tamper == "actor":
                await db.execute(update(CustodyEntry).where(CustodyEntry.seq == 3).values(actor="otro"))
            elif tamper == "delete_middle":
                await db.execute(delete(CustodyEntry).where(CustodyEntry.seq == 2))
            elif tamper == "delete_tail":
                await db.execute(delete(CustodyEntry).where(CustodyEntry.seq == 4))
            else:
                await db.execute(update(CustodyEntry).where(CustodyEntry.seq == 2).values(signature="00" * 64))
            await db.commit()
            res = await custody.verify(db, ORG)
            if tamper == "delete_tail":
                assert res["ok"]  # sin ancla, borrar el final no se nota desde adentro
                res = await custody.verify(db, ORG, expected_count=anchor["entries"], expected_head=anchor["head_hash"])
                assert not res["ok"] and res["anchor_checked"]
            else:
                assert not res["ok"], tamper
    run_db(go)


def test_anchor_is_signed_and_checks_out():
    async def go(factory):
        await seed_chain(factory)
        async with factory() as db:
            a = await custody.anchor(db, ORG)
            msg = core.anchor_message(ORG, a["entries"], a["head_hash"], a["generated_at"])
            assert core.verify_bytes(core.public_key_hex(), msg, a["signature"])
            assert (await custody.verify(db, ORG, a["entries"], a["head_hash"]))["ok"]
    run_db(go)


def test_list_entries_filters():
    async def go(factory):
        await seed_chain(factory)
        async with factory() as db:
            total, rows = await custody.list_entries(db, ORG, limit=2, offset=0)
            assert total == 4 and [r.seq for r in rows] == [4, 3]
            total, rows = await custody.list_entries(db, ORG, subject_id="s1")
            assert total == 1 and rows[0].subject_id == "s1"
            d = custody.entry_to_dict(rows[0])
            assert d["refs"] == ["asset:a1"] and d["payload"] == {"n": 1}
    run_db(go)


def make_case(alert_id="al-1"):
    now = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.timezone.utc)
    case = Case(id="case-1", organization_id=ORG, title="Fuerza bruta en VPN", description="d", priority=CasePriority.high,
                status=CaseStatus.open, assignee="ana", alert_id=alert_id, source="manual", created_at=now, updated_at=now)
    case.timeline = []
    return case


def test_evidence_package_has_selective_disclosure():
    async def go(factory):
        async with factory() as db:
            case = make_case()
            await custody.record_case_event(db, case, "case.created", "ana")
            await custody.append(db, ORG, "alert.created", source="siem-service", subject_type="alert",
                                 subject_id="al-1", refs=["alert:al-1"], payload={"rule": "ssh brute"})
            await custody.append(db, ORG, "vuln.status_changed", source="vuln-service", subject_type="vuln",
                                 subject_id="v-9", refs=["vuln:v-9"], payload={"secreto": "de otro caso"})
            await custody.append(db, ORG, "soar.playbook_run", source="soar-service", subject_type="playbook_run",
                                 subject_id="r1", refs=["alert:al-1"], payload={"status": "completed"})
            data, manifest = await custody.build_evidence_package(db, case, "ana")
            await db.commit()
            zf = zipfile.ZipFile(io.BytesIO(data))
            assert set(zf.namelist()) == {"manifest.json", "entries.csv", "LEEME.txt", "verificar_evidencia.py"}
            m = json.loads(zf.read("manifest.json"))
            by_type = {r["fields"]["type"]: r for r in m["chain"] if "fields" in r}
            assert set(by_type) == {"case.created", "alert.created", "soar.playbook_run", "evidence.exported"}
            hidden = [r for r in m["chain"] if "fields" not in r]
            assert len(hidden) == 1 and set(hidden[0]) == {"seq", "ts", "prev", "leaf", "entry_hash", "signature"}
            assert "de otro caso" not in zf.read("manifest.json").decode()
            assert "de otro caso" not in zf.read("entries.csv").decode()
            assert m["export_seq"] == len(m["chain"])
            assert m["anchor"]["entries"] == len(m["chain"])
            assert m["key_fingerprint"] == core.key_fingerprint(core.public_key_hex())
            # la exportacion quedo anotada en la cadena
            assert (await custody.verify(db, ORG))["ok"]
            total, rows = await custody.list_entries(db, ORG, event_type="evidence.exported")
            assert total == 1
    run_db(go)
