"""El userinfo ("x@") no puede esconder un host interno del denylist."""
import pytest
from app.target_validation import reject_dangerous_network_target


@pytest.mark.parametrize("target", [
    "http://x@auth-service:8000/",
    "http://x:y@postgres:5432/",
    "http://x@169.254.169.254/latest/meta-data/",
    "http://x@redis:6379",
    "http://x@127.0.0.1:80/",
])
def test_userinfo_does_not_bypass_denylist(target):
    with pytest.raises(ValueError):
        reject_dangerous_network_target(target)


def test_plain_public_target_still_allowed():
    reject_dangerous_network_target("https://example.com/path?next=http://postgres")
