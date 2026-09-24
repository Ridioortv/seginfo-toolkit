"""Tests para backend/shared/security.py: hashing de contraseñas y JWT.

Corre 100% local (sin DB, sin red) -- son las funciones puras/deterministicas
que TODOS los microservicios importan via app/dependencies.py para validar
el token de cada request.
"""
import time

import pytest
from jose import jwt
from jose.exceptions import ExpiredSignatureError

from backend.shared import security


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        hashed = security.hash_password("Sup3r$ecreta!")
        assert hashed != "Sup3r$ecreta!"
        assert hashed.startswith("$2b$")  # bcrypt

    def test_verify_correct_password(self):
        hashed = security.hash_password("Sup3r$ecreta!")
        assert security.verify_password("Sup3r$ecreta!", hashed) is True

    def test_verify_wrong_password(self):
        hashed = security.hash_password("Sup3r$ecreta!")
        assert security.verify_password("otra-cosa", hashed) is False

    def test_hash_is_salted(self):
        # Dos hashes de la misma contraseña deben diferir (salt distinto por
        # llamada) -- si esto alguna vez da False, bcrypt dejo de salar.
        h1 = security.hash_password("misma-clave")
        h2 = security.hash_password("misma-clave")
        assert h1 != h2
        assert security.verify_password("misma-clave", h1)
        assert security.verify_password("misma-clave", h2)


class TestAccessToken:
    def test_roundtrip_basic_claims(self):
        token = security.create_access_token(subject="user-123", role="analyst")
        payload = security.decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["role"] == "analyst"
        assert payload["type"] == "access"
        # org_id/platform_admin son opcionales: si no se pasan, no deben
        # aparecer en el payload (evita romper JWT de servicio-a-servicio
        # ya existentes que llaman create_access_token con solo subject/role).
        assert "org_id" not in payload
        assert "platform_admin" not in payload

    def test_includes_org_id_when_given(self):
        token = security.create_access_token(subject="user-123", role="analyst", org_id="org-abc")
        payload = security.decode_token(token)
        assert payload["org_id"] == "org-abc"

    def test_includes_platform_admin_flag_only_when_true(self):
        token = security.create_access_token(subject="root", role="admin", platform_admin=True)
        payload = security.decode_token(token)
        assert payload["platform_admin"] is True

        token_normal = security.create_access_token(subject="user-123", role="analyst", platform_admin=False)
        payload_normal = security.decode_token(token_normal)
        assert "platform_admin" not in payload_normal

    def test_expired_token_is_rejected(self):
        # Token ya vencido (exp en el pasado): decode_token debe fallar, no
        # devolver el payload igual.
        from datetime import timedelta

        expired = security.create_token("user-123", timedelta(seconds=-10), {"type": "access"})
        with pytest.raises(ExpiredSignatureError):
            security.decode_token(expired)

    def test_tampered_signature_is_rejected(self):
        # No tocar el ULTIMO caracter del token: en base64url, la posicion
        # final de un grupo puede caer en bits de padding no significativos,
        # asi que cambiarla no siempre altera el valor decodificado (test
        # flaky). Se tamperea el PRIMER caracter de la firma en cambio, que
        # siempre es significativo.
        token = security.create_access_token(subject="user-123", role="analyst")
        header, payload, signature = token.split(".")
        tampered_char = "A" if signature[0] != "A" else "B"
        tampered = f"{header}.{payload}.{tampered_char}{signature[1:]}"
        with pytest.raises(jwt.JWTError):
            security.decode_token(tampered)


class TestRefreshToken:
    def test_refresh_token_type_claim(self):
        token = security.create_refresh_token(subject="user-123")
        payload = security.decode_token(token)
        assert payload["type"] == "refresh"
        assert payload["sub"] == "user-123"

    def test_refresh_token_outlives_access_token(self):
        access = security.decode_token(security.create_access_token(subject="u", role="analyst"))
        refresh = security.decode_token(security.create_refresh_token(subject="u"))
        assert refresh["exp"] > access["exp"]
