from app.scanners.zeek import resolve_interface


def test_named_interface_is_used_as_is():
    assert resolve_interface("eth1") == "eth1"


def test_auto_picks_first_non_loopback():
    assert resolve_interface("auto", list_interfaces=lambda: ["lo", "eth0"]) == "eth0"


def test_ip_target_not_in_container_falls_back_to_auto():
    assert resolve_interface(
        "192.168.0.143", list_interfaces=lambda: ["lo", "eth0"], interface_for_ip=lambda ip: None
    ) == "eth0"


def test_ip_target_matching_container_interface():
    assert resolve_interface(
        "172.18.0.5", list_interfaces=lambda: ["lo", "eth0", "eth1"], interface_for_ip=lambda ip: "eth1"
    ) == "eth1"


def test_no_interfaces_returns_none():
    assert resolve_interface("auto", list_interfaces=lambda: ["lo"]) is None
