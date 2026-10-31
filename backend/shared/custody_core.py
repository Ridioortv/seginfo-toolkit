"""Nucleo de la CADENA DE CUSTODIA digital de TERO (funciones puras, sin base de datos).

Que resuelve: poder demostrarle a un tercero (auditor, cliente, juez) que lo que ocurrio en un caso
-- alertas, acciones de respuesta, cambios de estado, cierres de vulnerabilidades -- quedo registrado
en su momento y no se modifico despues.

Diseno (todo verificable SIN ningun secreto, solo con la clave publica):
  * Cada evento es una "hoja": leaf = SHA-256 del JSON canonico de sus campos (tipo, actor, servicio,
    sujeto, referencias, hash del payload).
  * La entrada de la cadena es entry_hash = SHA-256 de (version, organizacion, seq, ts, prev, leaf).
    prev es el entry_hash de la entrada anterior (la primera usa 64 ceros): borrar o reordenar algo
    rompe todo lo que sigue.
  * entry_hash se firma con Ed25519. La clave privada se deriva de un secreto de la instalacion que
    NO esta en la base de datos; la clave publica se puede publicar y entregar a cualquier auditor.
  * Divulgacion selectiva: como entry_hash depende solo de `leaf` (no de los campos), un paquete de
    evidencia puede mostrar completos los eventos de UN caso y, del resto de la cadena, solo
    (seq, ts, prev, leaf, entry_hash, firma): se prueba que la cadena esta entera sin revelar datos
    de otros casos.

Limite que hay que decir en voz alta: quien tenga el secreto de firma del servidor (o el servidor
mismo, con permisos de administrador) podria rehacer una cadena entera. Por eso conviene guardar
por fuera el "ancla" (cantidad + hash final) y usar CUSTODY_SIGNING_SEED propio en vez de derivarlo
del JWT."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS_HASH = "0" * 64
CUSTODY_VERSION = 1
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_REFS = 20
MAX_REF_LEN = 120


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical(obj) -> str:
    """JSON canonico: claves ordenadas, sin espacios, ASCII puro (los acentos salen como \\uXXXX)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_refs(refs) -> list[str]:
    """Referencias cruzadas ("case:<id>", "alert:<id>", "vuln:<id>", "asset:<id>"): unicas, ordenadas y acotadas."""
    clean = sorted({str(r).strip()[:MAX_REF_LEN] for r in (refs or []) if str(r).strip()})
    return clean[:MAX_REFS]


def payload_text(payload: dict | None) -> str:
    return canonical(payload or {})


def leaf_fields(event_type: str, actor: str, source: str, subject_type: str, subject_id: str,
                refs: list[str], payload_sha256: str) -> dict:
    return {
        "type": event_type, "actor": actor, "source": source,
        "subject_type": subject_type, "subject_id": subject_id,
        "refs": refs, "payload_sha256": payload_sha256,
    }


def leaf_hash(fields: dict) -> str:
    return sha256_hex(canonical(fields))


def entry_core(org: str | None, seq: int, ts: str, prev: str, leaf: str) -> dict:
    return {"v": CUSTODY_VERSION, "org": org or "", "seq": seq, "ts": ts, "prev": prev, "leaf": leaf}


def entry_hash(org: str | None, seq: int, ts: str, prev: str, leaf: str) -> str:
    return sha256_hex(canonical(entry_core(org, seq, ts, prev, leaf)))


def anchor_message(org: str | None, count: int, head_hash: str, generated_at: str) -> bytes:
    return f"tero-anchor|{org or ''}|{count}|{head_hash}|{generated_at}".encode()


# --- Claves ---------------------------------------------------------------------------------------

def _seed_secret() -> bytes:
    explicit = os.getenv("CUSTODY_SIGNING_SEED", "").strip()
    if explicit:
        return explicit.encode()
    from backend.shared.security import JWT_SECRET_KEY  # import perezoso: los tests del nucleo no lo necesitan
    return JWT_SECRET_KEY.encode()


def private_key() -> Ed25519PrivateKey:
    seed = hmac.new(_seed_secret(), b"tero-custody-ed25519-v1", hashlib.sha256).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_hex() -> str:
    raw = private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return raw.hex()


def key_fingerprint(pub_hex: str) -> str:
    """Huella corta y legible de la clave publica: SHA-256, 8 grupos de 4 hex (ej. 9f3a-01bc-...)."""
    digest = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]
    return "-".join(digest[i:i + 4] for i in range(0, 32, 4))


def key_is_derived_from_jwt() -> bool:
    return not os.getenv("CUSTODY_SIGNING_SEED", "").strip()


def sign_hex(message_hex: str) -> str:
    return private_key().sign(bytes.fromhex(message_hex)).hex()


def sign_bytes(message: bytes) -> str:
    return private_key().sign(message).hex()


def verify_hex(pub_hex: str, message_hex: str, signature_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(signature_hex), bytes.fromhex(message_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_bytes(pub_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# --- Verificacion de una cadena (filas con seq, ts, prev, leaf, entry_hash, signature) -------------

def verify_chain_rows(rows: list[dict], org: str | None, pub_hex: str) -> dict:
    """Recorre la cadena completa desde el genesis. Devuelve el primer punto roto y el motivo."""
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for r in rows:
        if r["seq"] != expected_seq:
            return _broken(rows, r["seq"], "falta una o mas entradas (secuencia interrumpida)")
        if r["prev"] != expected_prev:
            return _broken(rows, r["seq"], "el encadenado no coincide con la entrada anterior")
        recomputed = entry_hash(org, r["seq"], r["ts"], r["prev"], r["leaf"])
        if not hmac.compare_digest(recomputed, r["entry_hash"]):
            return _broken(rows, r["seq"], "el contenido de la entrada fue modificado")
        if not verify_hex(pub_hex, r["entry_hash"], r["signature"]):
            return _broken(rows, r["seq"], "la firma no es valida (no la genero este sistema)")
        expected_prev = r["entry_hash"]
        expected_seq += 1
    return {"ok": True, "entries": len(rows), "head_hash": expected_prev if rows else GENESIS_HASH,
            "broken_at_seq": None, "reason": ""}


def _broken(rows: list[dict], seq: int, reason: str) -> dict:
    return {"ok": False, "entries": len(rows), "head_hash": rows[-1]["entry_hash"] if rows else GENESIS_HASH,
            "broken_at_seq": seq, "reason": reason}


# --- Atestados firmados (soberania, cumplimiento, simulacros, cierres) ---------------------------------
# Un atestado es un documento JSON firmado con la misma clave Ed25519 de la cadena: lo que TERO afirma en un
# momento dado ("estas son las salidas a internet que observe", "este es el estado de cumplimiento"). Se
# puede verificar sin TERO con verificar_evidencia.py.

ATTESTATION_VERSION = 1
ATTESTATION_KINDS = ("sovereignty", "compliance", "drill", "closure", "vendor", "risk_exception", "executive", "partner")


def attestation_message(kind: str, org: str | None, generated_at: str, body: dict) -> bytes:
    return ("tero-attestation|" + canonical({
        "v": ATTESTATION_VERSION, "kind": kind, "org": org or "", "generated_at": generated_at, "body": body,
    })).encode()


def make_attestation(kind: str, org: str | None, body: dict) -> dict:
    generated_at = now_ts()
    pub = public_key_hex()
    # El cuerpo se pasa por JSON para firmar exactamente lo que despues se lee (fechas y numeros incluidos).
    clean = json.loads(canonical(body))
    return {
        "format": "tero-attestation", "version": ATTESTATION_VERSION, "kind": kind,
        "organization_id": org or "", "generated_at": generated_at, "body": clean,
        "public_key": pub, "key_fingerprint": key_fingerprint(pub),
        "signature": sign_bytes(attestation_message(kind, org, generated_at, clean)),
    }


def verify_attestation(doc: dict, expected_fingerprint: str = "") -> dict:
    try:
        ok = (doc.get("format") == "tero-attestation" and doc.get("version") == ATTESTATION_VERSION
              and verify_bytes(doc["public_key"],
                               attestation_message(doc["kind"], doc.get("organization_id"), doc["generated_at"], doc["body"]),
                               doc["signature"]))
        fp = key_fingerprint(doc["public_key"])
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "fingerprint": "", "reason": "documento mal formado"}
    if not ok:
        return {"ok": False, "fingerprint": fp, "reason": "la firma no es valida: el documento fue modificado o no lo firmo esta clave"}
    if expected_fingerprint and expected_fingerprint.strip().lower() != fp:
        return {"ok": False, "fingerprint": fp, "reason": "la huella de la clave no es la esperada"}
    return {"ok": True, "fingerprint": fp, "reason": ""}
