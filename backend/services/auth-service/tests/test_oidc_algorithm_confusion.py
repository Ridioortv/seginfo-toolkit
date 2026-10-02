"""Tests de seguridad para app/oidc.py: seleccion del algoritmo de firma al
validar un id_token de SSO (validate_id_token / _select_signing_algorithm).

Bug real encontrado: la lista de algoritmos PERMITIDOS para verificar la
firma se armaba a partir de `alg` del HEADER del propio id_token
(algorithms=[unverified_header.get("alg", "RS256")]) -- un dato que en ese
punto todavia no esta verificado. Si el algoritmo permitido es exactamente
"lo que diga el atacante", esa verificacion es un placebo: es la base de un
ataque de confusion de algoritmo (RS256 -> HS256, firmando con la clave
PUBLICA del proveedor -- publica en su propio JWKS -- como si fuera un
secreto HMAC). La version de python-jose fijada en requirements.txt
(3.3.0) bloquea por su cuenta la variante mas directa de este ataque (su
HMACKey exige kty=='oct', ver jose/backends/native.py::HMACKey._process_jwk)
-- pero el codigo seguia confiando en un dato no verificado para una
decision de seguridad, un patron fragil que no depende de nada que este
modulo controle.

El fix (_select_signing_algorithm) fuerza el algoritmo a venir SIEMPRE del
JWKS del proveedor (bajado por este servidor via HTTPS, nunca del id_token
sin verificar) y restringido a una lista de algoritmos asimetricos
conocidos. Sin red, sin DB."""
import asyncio
import base64
import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt as jose_jwt
from jose.utils import long_to_base64

from app import oidc


def _make_rsa_jwk(kid: str = "kid1", declared_alg: str | None = "RS256"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    jwk_entry = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "n": long_to_base64(numbers.n).decode(),
        "e": long_to_base64(numbers.e).decode(),
    }
    if declared_alg is not None:
        jwk_entry["alg"] = declared_alg
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jwk_entry, private_pem, public_pem


def _sign_id_token(private_pem: bytes, header_extra: dict, claims: dict, algorithm: str = "RS256") -> str:
    return jose_jwt.encode(claims, private_pem.decode(), algorithm=algorithm, headers=header_extra)


def _patch_discovery(monkeypatch, jwk_entry: dict):
    async def fake_discover(issuer):
        return {
            "jwks_uri": "https://issuer.example/jwks",
            "token_endpoint": "https://issuer.example/token",
            "authorization_endpoint": "https://issuer.example/authorize",
        }

    async def fake_fetch_jwks(jwks_uri):
        return {"keys": [jwk_entry]}

    monkeypatch.setattr(oidc, "discover", fake_discover)
    monkeypatch.setattr(oidc, "fetch_jwks", fake_fetch_jwks)


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _forge_hs256_token_signed_with_public_key(public_pem: bytes, kid: str, claims: dict) -> str:
    """Construye a mano (sin pasar por jose, que ya rechaza esto en el lado
    de la firma) el PoC clasico de confusion de algoritmo: header
    alg=HS256, firmado con HMAC-SHA256 usando la clave PUBLICA del
    proveedor (publica, esta en su JWKS) como si fuera un secreto
    compartido."""
    header = {"alg": "HS256", "kid": kid, "typ": "JWT"}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = header_b64 + b"." + payload_b64
    signature = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode()


class TestSelectSigningAlgorithm:
    """_select_signing_algorithm es logica pura (sin red/DB) -- se puede
    probar directamente, igual que is_valid_status_transition en
    case-service o can_set_active_state en asset-service."""

    def test_uses_the_jwks_declared_algorithm_when_allowed(self):
        assert oidc._select_signing_algorithm({"kty": "RSA", "alg": "RS256"}) == "RS256"
        assert oidc._select_signing_algorithm({"kty": "EC", "alg": "ES384"}) == "ES384"

    def test_falls_back_to_kty_based_default_when_alg_is_missing(self):
        assert oidc._select_signing_algorithm({"kty": "RSA"}) == "RS256"
        assert oidc._select_signing_algorithm({"kty": "EC"}) == "ES256"

    def test_never_returns_a_symmetric_or_none_algorithm(self):
        # Ni un JWKS "raro" que declare HS256/none puede hacer que esto
        # devuelva algo distinto de un algoritmo asimetrico conocido (o
        # None, que el caller trata como error) -- este es exactamente el
        # hueco que tenia el codigo viejo via el header del id_token.
        assert oidc._select_signing_algorithm({"kty": "RSA", "alg": "HS256"}) == "RS256"  # cae al default seguro por kty
        assert oidc._select_signing_algorithm({"kty": "oct", "alg": "HS256"}) is None
        assert oidc._select_signing_algorithm({"kty": "RSA", "alg": "none"}) == "RS256"
        assert oidc._select_signing_algorithm({"kty": "unknown-kty"}) is None


class TestValidateIdTokenAlgorithmComesFromTrustedJwks:
    CONFIG = SimpleNamespace(issuer="https://issuer.example", client_id="client-123")
    NOW = int(time.time())

    def test_legit_rs256_token_is_still_accepted(self, monkeypatch):
        jwk_entry, private_pem, _ = _make_rsa_jwk(declared_alg="RS256")
        _patch_discovery(monkeypatch, jwk_entry)
        token = _sign_id_token(
            private_pem, {"kid": "kid1"},
            {"iss": self.CONFIG.issuer, "aud": self.CONFIG.client_id, "nonce": "nonce1",
             "email": "user@acme.com", "exp": self.NOW + 300, "iat": self.NOW},
            algorithm="RS256",
        )
        claims = asyncio.run(oidc.validate_id_token(self.CONFIG, token, "nonce1"))
        assert claims["email"] == "user@acme.com"

    def test_algorithm_confusion_forgery_is_rejected(self, monkeypatch):
        # El PoC clasico: id_token con alg=HS256, firmado con HMAC usando
        # la clave PUBLICA del proveedor como "secreto". Con el fix, los
        # algoritmos permitidos para verificar vienen SIEMPRE del JWKS
        # (RS256 aca) y nunca del header del propio token -- jose rechaza
        # la verificacion porque "HS256" no esta en algorithms=["RS256"],
        # sin que esto dependa de ninguna proteccion interna especifica de
        # la libreria sobre el tipo de la key.
        jwk_entry, _, public_pem = _make_rsa_jwk(declared_alg="RS256")
        _patch_discovery(monkeypatch, jwk_entry)
        forged = _forge_hs256_token_signed_with_public_key(
            public_pem, "kid1",
            {"iss": self.CONFIG.issuer, "aud": self.CONFIG.client_id, "nonce": "nonce1",
             "email": "victim@acme.com", "exp": self.NOW + 300, "iat": self.NOW},
        )
        with pytest.raises(oidc.OidcError):
            asyncio.run(oidc.validate_id_token(self.CONFIG, forged, "nonce1"))

    def test_jwks_key_without_alg_falls_back_to_kty_based_default(self, monkeypatch):
        jwk_entry, private_pem, _ = _make_rsa_jwk(declared_alg=None)
        _patch_discovery(monkeypatch, jwk_entry)
        token = _sign_id_token(
            private_pem, {"kid": "kid1"},
            {"iss": self.CONFIG.issuer, "aud": self.CONFIG.client_id, "nonce": "nonce1",
             "email": "user@acme.com", "exp": self.NOW + 300, "iat": self.NOW},
            algorithm="RS256",
        )
        claims = asyncio.run(oidc.validate_id_token(self.CONFIG, token, "nonce1"))
        assert claims["email"] == "user@acme.com"

    def test_decode_never_receives_algorithms_from_the_token_header(self, monkeypatch):
        jwk_entry, private_pem, _ = _make_rsa_jwk(declared_alg="RS256")
        _patch_discovery(monkeypatch, jwk_entry)

        captured = {}
        real_decode = jose_jwt.decode

        def spy_decode(token, key, algorithms, **kwargs):
            captured["algorithms"] = list(algorithms)
            return real_decode(token, key, algorithms=algorithms, **kwargs)

        monkeypatch.setattr(oidc.jose_jwt, "decode", spy_decode)
        token = _sign_id_token(
            private_pem, {"kid": "kid1"},
            {"iss": self.CONFIG.issuer, "aud": self.CONFIG.client_id, "nonce": "nonce1",
             "email": "user@acme.com", "exp": self.NOW + 300, "iat": self.NOW},
            algorithm="RS256",
        )
        asyncio.run(oidc.validate_id_token(self.CONFIG, token, "nonce1"))
        assert captured["algorithms"] == ["RS256"]
