"""El verificador independiente (solo biblioteca estandar) frente a paquetes reales y manipulados."""
import copy
import datetime as dt
import io
import json
import os
import subprocess
import sys
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app import custody_service as custody
from app.assets import verificar_evidencia as ver
from app.models import Case, CasePriority, CaseStatus
from backend.shared import custody_core as core
from custody_helpers import run_db

ORG = "org-1"


@pytest.fixture(autouse=True)
def seed(monkeypatch):
    monkeypatch.setenv("CUSTODY_SIGNING_SEED", "semilla-de-prueba")


def test_pure_python_ed25519_matches_cryptography():
    for i in range(12):
        key = Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        msg = os.urandom(i * 7)
        sig = key.sign(msg)
        assert ver.ed25519_verify(pub, msg, sig)
        assert not ver.ed25519_verify(pub, msg + b"x", sig)
        bad = bytearray(sig)
        bad[5] ^= 1
        assert not ver.ed25519_verify(pub, msg, bytes(bad))
        assert not ver.ed25519_verify(pub, msg, sig[:63])
        assert not ver.ed25519_verify(pub[:31], msg, sig)


def test_rfc8032_test_vector():
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ver.ed25519_verify(pub, b"", sig)


def make_package():
    async def go(factory):
        async with factory() as db:
            now = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.timezone.utc)
            case = Case(id="case-1", organization_id=ORG, title="Fuerza bruta", description="d", priority=CasePriority.high,
                        status=CaseStatus.open, assignee="ana", alert_id="al-1", source="manual", created_at=now, updated_at=now)
            case.timeline = []
            await custody.record_case_event(db, case, "case.created", "ana")
            await custody.append(db, ORG, "alert.created", source="siem-service", subject_type="alert", subject_id="al-1",
                                 refs=["alert:al-1"], payload={"rule": "ssh brute", "ñ": "acentos ó"})
            await custody.append(db, ORG, "vuln.status_changed", source="vuln-service", subject_type="vuln",
                                 subject_id="v-9", refs=["vuln:v-9"], payload={"x": 1})
            data, manifest = await custody.build_evidence_package(db, case, "ana")
            return data
    return run_db(go)


@pytest.fixture(scope="module")
def package_bytes(monkeypatch_module=None):
    os.environ["CUSTODY_SIGNING_SEED"] = "semilla-de-prueba"
    try:
        return make_package()
    finally:
        pass


def manifest_of(data):
    return json.loads(zipfile.ZipFile(io.BytesIO(data)).read("manifest.json"))


def test_valid_package_passes_all_checks(package_bytes):
    res = ver.verify_manifest(manifest_of(package_bytes))
    assert res["ok"], res["checks"]
    assert len(res["checks"]) == 5 and res["disclosed"] == 3 and res["entries"] == 4
    assert res["fingerprint"] == core.key_fingerprint(core.public_key_hex())


def test_expected_fingerprint(package_bytes):
    m = manifest_of(package_bytes)
    fp = core.key_fingerprint(core.public_key_hex())
    assert ver.verify_manifest(m, fp)["ok"]
    assert ver.verify_manifest(m, fp.replace("-", "").upper())["ok"]
    assert not ver.verify_manifest(m, "0000-0000-0000-0000-0000-0000-0000-0000")["ok"]


def failed_names(res):
    return {c["name"] for c in res["checks"] if not c["ok"]}


def test_editing_the_case_snapshot_is_detected(package_bytes):
    m = manifest_of(package_bytes)
    m["case"]["status"] = "closed"
    res = ver.verify_manifest(m)
    assert not res["ok"] and "La ficha del caso es la que se firmo al exportar" in failed_names(res)


def test_editing_a_disclosed_event_is_detected(package_bytes):
    m = manifest_of(package_bytes)
    row = next(r for r in m["chain"] if r.get("fields", {}).get("type") == "alert.created")
    row["payload"] = row["payload"].replace("ssh brute", "todo normal")
    res = ver.verify_manifest(m)
    assert not res["ok"] and "Los eventos mostrados son los que se firmaron" in failed_names(res)
    row["fields"]["actor"] = "otro"
    assert not ver.verify_manifest(m)["ok"]


def test_removing_or_reordering_entries_is_detected(package_bytes):
    m = manifest_of(package_bytes)
    for mutate in (lambda c: c.pop(1), lambda c: c.reverse(), lambda c: c.pop()):
        broken = copy.deepcopy(m)
        mutate(broken["chain"])
        res = ver.verify_manifest(broken)
        assert not res["ok"], mutate


def test_changing_a_hidden_entry_is_detected(package_bytes):
    m = manifest_of(package_bytes)
    hidden = next(r for r in m["chain"] if "fields" not in r)
    hidden["leaf"] = "f" * 64
    assert not ver.verify_manifest(m)["ok"]


def test_forging_with_another_key_is_detected(package_bytes):
    m = manifest_of(package_bytes)
    other = Ed25519PrivateKey.generate()
    pub = other.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    m["public_key"] = pub  # sustituir la clave: ya ninguna firma coincide
    res = ver.verify_manifest(m)
    assert not res["ok"] and "Cadena completa y firmada (encadenado + Ed25519)" in failed_names(res)


def test_anchor_tampering_is_detected(package_bytes):
    m = manifest_of(package_bytes)
    m["anchor"]["entries"] += 1
    res = ver.verify_manifest(m)
    assert not res["ok"] and "Ancla (cantidad + hash final) firmada" in failed_names(res)


def test_garbage_manifests_do_not_crash():
    for bad in ({}, {"format": "tero-evidence-package", "version": 1}, {"format": "otra-cosa"}):
        assert not ver.verify_manifest(bad)["ok"]


def test_cli_runs_standalone_on_the_zip(package_bytes, tmp_path):
    zpath = tmp_path / "evidencia.zip"
    zpath.write_bytes(package_bytes)
    script = tmp_path / "verificar_evidencia.py"
    script.write_text(zipfile.ZipFile(zpath).read("verificar_evidencia.py").decode())
    out = subprocess.run([sys.executable, "-I", str(script), str(zpath)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "EVIDENCIA INTEGRA" in out.stdout
    # paquete adulterado: el zip rearmado con otra ficha de caso falla con codigo 1
    m = manifest_of(package_bytes)
    m["case"]["title"] = "otro titulo"
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("manifest.json", json.dumps(m))
    out = subprocess.run([sys.executable, "-I", str(script), str(bad)], capture_output=True, text=True)
    assert out.returncode == 1 and "NO CONFIABLE" in out.stdout
    assert subprocess.run([sys.executable, "-I", str(script), str(tmp_path / "no-existe.zip")],
                          capture_output=True, text=True).returncode == 2
