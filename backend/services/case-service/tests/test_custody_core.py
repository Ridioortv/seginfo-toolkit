"""Nucleo criptografico de la cadena de custodia: determinismo, firmas, deteccion de manipulacion."""
import hashlib

import pytest

from backend.shared import custody_core as core


@pytest.fixture(autouse=True)
def seed(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")


def build_rows(n=3, org="org-1"):
    rows, prev = [], core.GENESIS_HASH
    for i in range(1, n + 1):
        leaf = core.leaf_hash(core.leaf_fields("scan.completed", "sys", "scan-service", "scan", f"s{i}", [], "0" * 64))
        ts = f"2026-10-0{i}T10:00:00.000000Z"
        h = core.entry_hash(org, i, ts, prev, leaf)
        rows.append({"seq": i, "ts": ts, "prev": prev, "leaf": leaf, "entry_hash": h, "signature": core.sign_hex(h)})
        prev = h
    return rows


def test_canonical_is_stable_and_ascii():
    assert core.canonical({"b": 1, "a": "á"}) == '{"a":"\\u00e1","b":1}'
    assert core.canonical({"a": 1, "b": 2}) == core.canonical({"b": 2, "a": 1})


def test_key_is_deterministic_and_depends_on_seed(monkeypatch):
    first = core.public_key_hex()
    assert first == core.public_key_hex()
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "otra-semilla")
    assert core.public_key_hex() != first
    assert core.key_is_derived_from_jwt() is False
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "")
    assert core.key_is_derived_from_jwt() is True


def test_fingerprint_format():
    fp = core.key_fingerprint(core.public_key_hex())
    assert len(fp.split("-")) == 8 and all(len(g) == 4 for g in fp.split("-"))


def test_sign_and_verify_roundtrip_and_rejects_other_key(monkeypatch):
    msg = hashlib.sha256(b"x").hexdigest()
    sig = core.sign_hex(msg)
    pub = core.public_key_hex()
    assert core.verify_hex(pub, msg, sig)
    assert not core.verify_hex(pub, hashlib.sha256(b"y").hexdigest(), sig)
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "otra-semilla")
    assert not core.verify_hex(core.public_key_hex(), msg, sig)
    assert not core.verify_hex(pub, msg, "zz")  # entrada invalida no revienta


def test_normalize_refs_dedupes_sorts_and_limits():
    assert core.normalize_refs(["b", "a", "a", "", "  "]) == ["a", "b"]
    assert len(core.normalize_refs([f"r{i}" for i in range(50)])) == core.MAX_REFS
    assert all(len(r) <= core.MAX_REF_LEN for r in core.normalize_refs(["x" * 500]))


def test_valid_chain_verifies():
    rows = build_rows()
    res = core.verify_chain_rows(rows, "org-1", core.public_key_hex())
    assert res["ok"] and res["entries"] == 3 and res["head_hash"] == rows[-1]["entry_hash"]


@pytest.mark.parametrize("mutate,reason", [
    (lambda rows: rows.pop(1), "secuencia"),
    (lambda rows: rows[1].update(ts="2030-01-01T00:00:00.000000Z"), "modificado"),
    (lambda rows: rows[1].update(leaf="f" * 64), "modificado"),
    (lambda rows: rows[2].update(signature="00" * 64), "firma"),
    (lambda rows: rows.__setitem__(slice(0, 2), [rows[1], rows[0]]), "secuencia"),
])
def test_tampering_is_detected(mutate, reason):
    rows = build_rows()
    mutate(rows)
    res = core.verify_chain_rows(rows, "org-1", core.public_key_hex())
    assert not res["ok"] and reason in res["reason"]


def test_chain_from_another_org_or_key_fails(monkeypatch):
    rows = build_rows(org="org-1")
    assert not core.verify_chain_rows(rows, "org-2", core.public_key_hex())["ok"]
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "otra-semilla")
    assert not core.verify_chain_rows(rows, "org-1", core.public_key_hex())["ok"]


def test_rewriting_a_row_without_the_key_fails_signature(monkeypatch):
    # El atacante recalcula hashes coherentes pero no tiene la clave privada: la firma lo delata.
    rows = build_rows()
    leaf = core.leaf_hash(core.leaf_fields("scan.completed", "atacante", "x", "scan", "s2", [], "0" * 64))
    rows[1]["leaf"] = leaf
    rows[1]["entry_hash"] = core.entry_hash("org-1", 2, rows[1]["ts"], rows[1]["prev"], leaf)
    res = core.verify_chain_rows(rows, "org-1", core.public_key_hex())
    assert not res["ok"] and "firma" in res["reason"]
