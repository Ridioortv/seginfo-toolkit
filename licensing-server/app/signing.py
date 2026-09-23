"""Firma Ed25519 de las respuestas de /license/{license_key}/status.

LICENSE_SIGNING_PRIVATE_KEY (env var, base64 de 32 bytes) vive UNICAMENTE
en este servidor -- nunca se distribuye a los clientes. Lo que cada
cliente recibe (embebido en su .env al armar el .rar) es la clave
PUBLICA correspondiente (LICENSE_SERVER_PUBLIC_KEY en
backend/shared/license_check.py), que solo permite VERIFICAR una firma,
nunca fabricar una.

Generar un par de claves nuevo: `python generate_keys.py` en la raiz de
este servicio (ver ese script)."""
import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical_bytes(payload: dict) -> bytes:
    # Mismo formato exacto que backend/shared/license_check.py::_canonical_bytes
    # -- si estos dos alguna vez se desalinean, todo cliente rechaza la
    # firma como invalida (fail-closed, no fail-open: mejor eso que un
    # bug silencioso que deje pasar una firma mal verificada).
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _private_key() -> Ed25519PrivateKey:
    raw_b64 = os.getenv("LICENSE_SIGNING_PRIVATE_KEY", "")
    if not raw_b64:
        raise RuntimeError(
            "LICENSE_SIGNING_PRIVATE_KEY no esta configurado -- generar un par de "
            "claves con generate_keys.py y setear la privada aca (nunca en un "
            "cliente) y la publica en LICENSE_SERVER_PUBLIC_KEY de cada instalacion."
        )
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw_b64))


def sign_payload(payload: dict) -> str:
    signature = _private_key().sign(_canonical_bytes(payload))
    return base64.b64encode(signature).decode("ascii")
