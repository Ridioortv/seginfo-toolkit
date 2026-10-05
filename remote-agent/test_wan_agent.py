"""Tests del Agente WAN (AGENT_ROLE=wan) de remote-agent/agent.py: solo
objetivos publicos de internet. Sin red ni binarios."""
import importlib.util
import os
import pathlib

import pytest


def _load(role):
    os.environ["AGENT_ROLE"] = role
    spec = importlib.util.spec_from_file_location("agent_wan_test", pathlib.Path(__file__).parent / "agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def wan():
    yield _load("wan")
    os.environ.pop("AGENT_ROLE", None)


@pytest.mark.parametrize("scanner,target", [
    ("nuclei", "https://example.com"),
    ("nuclei", "8.8.8.8"),
    ("nuclei", "scanme.nmap.org"),
    ("zap", "https://app.cliente.com/login"),
    ("trivy", "alpine:3.18"),
    ("semgrep", "https://github.com/OWASP/NodeGoat.git"),
    ("gitleaks", "https://github.com/OWASP/NodeGoat.git"),
])
def test_public_targets_are_allowed(wan, scanner, target):
    assert wan._wan_rejection(scanner, target) is None


@pytest.mark.parametrize("scanner,target", [
    ("nuclei", "192.168.0.143"),
    ("nuclei", "http://192.168.0.143:5173"),
    ("nuclei", "192.168.0.0/24"),
    ("nuclei", "10.1.2.3"),
    ("nuclei", "172.16.5.5"),
    ("zap", "http://localhost:8080/x"),
    ("zap", "http://host.docker.internal:5173"),
    ("nuclei", "[::1]"),
    ("nuclei", "169.254.1.1"),
    ("nuclei", "intranet.empresa.local"),
    ("semgrep", "https://usuario:clave@192.168.1.5/repo.git"),
])
def test_private_or_internal_targets_are_rejected(wan, scanner, target):
    msg = wan._wan_rejection(scanner, target)
    assert msg and "Agente LAN" in msg


@pytest.mark.parametrize("scanner", ["zeek", "falco", "yara"])
def test_local_only_scanners_are_rejected(wan, scanner):
    msg = wan._wan_rejection(scanner, "auto")
    assert msg and scanner in msg


def test_other_roles_are_never_restricted():
    agent = _load("")
    try:
        assert agent._wan_rejection("nuclei", "192.168.0.1") is None
        assert agent._wan_rejection("zeek", "auto") is None
    finally:
        os.environ.pop("AGENT_ROLE", None)
