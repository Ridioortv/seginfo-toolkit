#!/usr/bin/env python3
"""Verificador INDEPENDIENTE de paquetes de evidencia de TERO Security.

Sirve para que un auditor, un cliente o un juez compruebe un paquete de evidencia SIN tener TERO
instalado y SIN ningun secreto: usa solo la biblioteca estandar de Python 3.8+ (la verificacion de
firmas Ed25519 esta implementada aca mismo, segun RFC 8032).

Uso:
    python verificar_evidencia.py evidencia-caso-xxxx.zip
    python verificar_evidencia.py manifest.json --huella 9f3a-01bc-...      # fija la clave esperada
    python verificar_evidencia.py evidencia-caso-xxxx.zip --json
    python verificar_evidencia.py atestado-soberania.json                   # atestados firmados (soberania, cumplimiento...)

Que comprueba (todo debe dar OK):
  1. La cadena de custodia esta completa desde el primer evento: cada entrada apunta a la anterior,
     la numeracion no tiene huecos y el hash de cada una se recalcula igual.
  2. Cada entrada esta firmada con la clave publica del paquete (Ed25519).
  3. Los eventos mostrados en el paquete son exactamente los que se firmaron (hash de contenido).
  4. La ficha del caso que figura en el paquete es la misma que se registro y firmo al exportar.
  5. El "ancla" (cantidad de entradas + hash final) esta firmada y coincide con la cadena.

IMPORTANTE: esto prueba que el paquete es integro y que lo firmo la clave publica incluida. Para
confirmar que esa clave es la de la instalacion de TERO que corresponde, compara la huella que
imprime este programa con la que muestra TERO en "Cadena de custodia" o con la que el emisor te
informo por otro canal (opcion --huella)."""
import argparse
import hashlib
import json
import sys
import zipfile

# --- Ed25519 (RFC 8032), solo verificacion ----------------------------------------------------------

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, point):
    result = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            result = _add(result, point)
        point = _add(point, point)
        s >>= 1
    return result


def _equal(a, b):
    if (a[0] * b[2] - b[0] * a[2]) % _P != 0:
        return False
    return (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _decompress(raw):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_point = _decompress(public_key)
    r_point = _decompress(signature[:32])
    if a_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(r_point, _mul(h, a_point)))


def _verify_hex(pub_hex, message: bytes, sig_hex) -> bool:
    try:
        return ed25519_verify(bytes.fromhex(pub_hex), message, bytes.fromhex(sig_hex))
    except (ValueError, TypeError):
        return False


# --- Formato del paquete (misma definicion que backend/shared/custody_core.py) -----------------------

GENESIS_HASH = "0" * 64
CUSTODY_VERSION = 1


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fingerprint(pub_hex: str) -> str:
    digest = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]
    return "-".join(digest[i:i + 4] for i in range(0, 32, 4))


ATTESTATION_VERSION = 1


def verify_attestation(doc: dict, expected_fingerprint: str = "") -> dict:
    """Atestado firmado (soberania, cumplimiento, simulacro, cierre): misma firma Ed25519, otro formato."""
    result = {"ok": False, "kind": "", "fingerprint": "", "generated_at": "", "reason": ""}
    try:
        message = ("tero-attestation|" + _canonical({
            "v": doc["version"], "kind": doc["kind"], "org": doc.get("organization_id") or "",
            "generated_at": doc["generated_at"], "body": doc["body"],
        })).encode()
        result.update(kind=doc["kind"], generated_at=doc["generated_at"], fingerprint=_fingerprint(doc["public_key"]))
        if doc.get("format") != "tero-attestation" or doc["version"] != ATTESTATION_VERSION:
            result["reason"] = "formato o version desconocidos"
        elif not _verify_hex(doc["public_key"], message, doc["signature"]):
            result["reason"] = "la firma no es valida: el documento fue modificado o no lo firmo esta clave"
        elif expected_fingerprint and expected_fingerprint.strip().lower() != result["fingerprint"]:
            result["reason"] = "la huella de la clave no es la esperada"
        else:
            result["ok"] = True
    except (KeyError, TypeError, ValueError):
        result["reason"] = "documento mal formado"
    return result


def load_manifest(path: str) -> dict:
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            with zf.open("manifest.json") as fh:
                return json.loads(fh.read().decode("utf-8"))
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def verify_manifest(manifest: dict, expected_fingerprint: str = "") -> dict:
    """Devuelve {"ok": bool, "checks": [(nombre, ok, detalle)], "fingerprint": str, ...}."""
    checks = []

    def check(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    result = {"ok": False, "checks": checks, "fingerprint": "", "case_id": "", "entries": 0, "disclosed": 0}

    try:
        if not check("Formato del paquete", manifest.get("format") == "tero-evidence-package"
                     and manifest.get("version") == 1, "se esperaba tero-evidence-package v1"):
            return result
        pub = manifest["public_key"]
        org = manifest.get("organization_id") or ""
        chain = manifest["chain"]
        case = manifest["case"]
        result["fingerprint"] = _fingerprint(pub)
        result["case_id"] = case.get("id", "")
        result["entries"] = len(chain)
    except (KeyError, ValueError, TypeError) as exc:
        check("Formato del paquete", False, f"faltan datos: {exc}")
        return result

    if expected_fingerprint:
        check("Huella de la clave publica", result["fingerprint"].replace("-", "").lower() ==
              expected_fingerprint.replace("-", "").lower(),
              f"la clave del paquete tiene la huella {result['fingerprint']}")

    # 1-2. Cadena completa + firmas
    prev, seq_expected, chain_ok, detail = GENESIS_HASH, 1, True, f"{len(chain)} entradas desde el primer evento"
    for row in chain:
        try:
            if row["seq"] != seq_expected:
                chain_ok, detail = False, f"falta una o mas entradas antes de la #{row['seq']}"
                break
            if row["prev"] != prev:
                chain_ok, detail = False, f"la entrada #{row['seq']} no encadena con la anterior"
                break
            recomputed = _sha256(_canonical({"v": CUSTODY_VERSION, "org": org, "seq": row["seq"], "ts": row["ts"],
                                             "prev": row["prev"], "leaf": row["leaf"]}))
            if recomputed != row["entry_hash"]:
                chain_ok, detail = False, f"la entrada #{row['seq']} fue modificada (el hash no coincide)"
                break
            if not _verify_hex(pub, bytes.fromhex(row["entry_hash"]), row["signature"]):
                chain_ok, detail = False, f"la firma de la entrada #{row['seq']} no es valida"
                break
        except (KeyError, ValueError, TypeError):
            chain_ok, detail = False, "una entrada de la cadena esta incompleta o mal formada"
            break
        prev, seq_expected = row["entry_hash"], seq_expected + 1
    if not chain:
        chain_ok, detail = False, "el paquete no trae cadena"
    check("Cadena completa y firmada (encadenado + Ed25519)", chain_ok, detail)

    # 3. Eventos mostrados == eventos firmados
    disclosed_ok, disclosed, detail = True, 0, ""
    for row in chain:
        fields = row.get("fields")
        if fields is None:
            continue
        disclosed += 1
        try:
            if _sha256(_canonical(fields)) != row["leaf"]:
                disclosed_ok, detail = False, f"el evento mostrado de la entrada #{row['seq']} no es el que se firmo"
                break
            payload = row.get("payload", "{}")
            if _sha256(payload) != fields["payload_sha256"]:
                disclosed_ok, detail = False, f"el detalle del evento #{row['seq']} fue alterado"
                break
        except (KeyError, TypeError):
            disclosed_ok, detail = False, f"el evento mostrado de la entrada #{row.get('seq')} esta mal formado"
            break
    result["disclosed"] = disclosed
    check("Los eventos mostrados son los que se firmaron", disclosed_ok,
          detail or f"{disclosed} eventos con su contenido completo")

    # 4. Ficha del caso == la que se firmo al exportar
    snap_ok, detail = False, "no se encontro la entrada de exportacion en la cadena"
    export_row = next((r for r in chain if r.get("seq") == manifest.get("export_seq")), None)
    if export_row is not None and export_row.get("fields", {}).get("type") == "evidence.exported":
        try:
            signed_hash = json.loads(export_row["payload"]).get("snapshot_sha256")
            actual = _sha256(_canonical(case))
            snap_ok = signed_hash == actual and manifest.get("snapshot_sha256") == actual
            detail = "la ficha del caso coincide con la registrada y firmada al exportar" if snap_ok \
                else "la ficha del caso fue modificada despues de exportarla"
        except (ValueError, TypeError, KeyError):
            detail = "la entrada de exportacion esta mal formada"
    check("La ficha del caso es la que se firmo al exportar", snap_ok, detail)

    # 5. Ancla firmada y coherente con la cadena
    anchor_ok, detail = False, "el paquete no trae ancla"
    anchor = manifest.get("anchor")
    if anchor and chain:
        try:
            message = f"tero-anchor|{org}|{anchor['entries']}|{anchor['head_hash']}|{anchor['generated_at']}".encode()
            sig_ok = _verify_hex(pub, message, anchor["signature"])
            same = anchor["entries"] == len(chain) and anchor["head_hash"] == chain[-1]["entry_hash"]
            anchor_ok = sig_ok and same
            detail = ("ancla firmada: %d entradas, hash final %s..." % (anchor["entries"], anchor["head_hash"][:16])
                      if anchor_ok else "el ancla no esta firmada por la clave del paquete o no coincide con la cadena")
        except (KeyError, TypeError):
            detail = "el ancla esta mal formada"
    check("Ancla (cantidad + hash final) firmada", anchor_ok, detail)

    result["ok"] = all(c["ok"] for c in checks)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verifica un paquete de evidencia de TERO Security")
    parser.add_argument("paquete", help="archivo .zip del paquete, su manifest.json o un atestado .json")
    parser.add_argument("--huella", default="", help="huella esperada de la clave publica (la que informa el emisor)")
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.paquete)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        print(f"No se pudo leer el paquete: {exc}", file=sys.stderr)
        return 2
    if manifest.get("format") == "tero-attestation":
        att = verify_attestation(manifest, args.huella)
        if args.json:
            print(json.dumps(att, ensure_ascii=False, indent=2))
        else:
            print("Verificacion de atestado - TERO Security")
            print("Tipo: %s  Generado: %s" % (att["kind"] or "?", att["generated_at"] or "?"))
            print("Huella de la clave publica: %s" % (att["fingerprint"] or "?"))
            print("RESULTADO: %s" % ("ATESTADO INTEGRO (la firma es valida)" if att["ok"] else "ATESTADO NO CONFIABLE: " + att["reason"]))
            if att["ok"]:
                print("Esto prueba que el contenido no cambio desde que TERO lo firmo; recorda confirmar la huella de la clave.")
        return 0 if att["ok"] else 1
    result = verify_manifest(manifest, args.huella)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("Verificacion de evidencia - TERO Security")
        print("Caso: %s" % (result["case_id"] or "?"))
        print("Huella de la clave publica: %s" % (result["fingerprint"] or "?"))
        for c in result["checks"]:
            print("  [%s] %s%s" % ("OK" if c["ok"] else "FALLO", c["name"], (" - " + c["detail"]) if c["detail"] else ""))
        print("RESULTADO: %s" % ("EVIDENCIA INTEGRA" if result["ok"] else "EVIDENCIA NO CONFIABLE (hay al menos un FALLO)"))
        if result["ok"]:
            print("Recorda confirmar que la huella coincide con la de la instalacion de TERO que corresponde.")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
