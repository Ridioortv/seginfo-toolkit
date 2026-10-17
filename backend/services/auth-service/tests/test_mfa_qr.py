"""El QR del MFA tiene que ser un otpauth:// estandar escaneable por apps TOTP."""
import base64
import re
from urllib.parse import parse_qs, urlparse

import pyotp

from app import services


def _enroll_url():
    secret = pyotp.random_base32()
    return secret, pyotp.TOTP(secret).provisioning_uri(name="manu@example.com", issuer_name="TERO Security")


def test_otpauth_url_is_standard_totp():
    secret, url = _enroll_url()
    parsed = urlparse(url)
    assert parsed.scheme == "otpauth" and parsed.netloc == "totp"
    q = parse_qs(parsed.query)
    assert q["secret"] == [secret]
    assert q["issuer"] == ["TERO Security"]


def test_qr_data_uri_is_valid_svg():
    _, url = _enroll_url()
    uri = services.mfa_qr_data_uri(url)
    assert uri.startswith("data:image/svg+xml;base64,")
    svg = base64.b64decode(uri.split(",", 1)[1]).decode("utf-8")
    assert "<svg" in svg and "</svg>" in svg
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg  # sin esto el <img> queda en blanco
    assert re.search(r"<path|<rect", svg)  # tiene modulos dibujados
