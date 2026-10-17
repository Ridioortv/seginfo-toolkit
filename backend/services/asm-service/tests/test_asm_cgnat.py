from app.services import is_blocked_target_ip


def test_cgnat_and_alibaba_metadata_blocked():
    assert is_blocked_target_ip("100.100.100.200")
    assert is_blocked_target_ip("100.64.0.1")
    assert not is_blocked_target_ip("8.8.8.8")
