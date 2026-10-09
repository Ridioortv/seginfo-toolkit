"""Tests de remote-agent/agent.py: inventario de paquetes de trivy y
--list-all-pkgs (para "Imagenes y Paquetes")."""
import json
import agent


RAW = json.dumps({
    "Results": [
        {"Target": "alpine:3.18 (alpine 3.18.4)", "Class": "os-pkgs", "Type": "alpine",
         "Packages": [{"Name": "musl", "Version": "1.2.4", "Arch": "x86_64", "Layer": {"DiffID": "sha256:abc"}},
                      {"Name": "busybox", "Version": "1.36"}],
         "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "musl", "Severity": "HIGH"}]},
        {"Target": "app", "Class": "lang-pkgs", "Type": "pip", "Packages": [{"Name": "flask", "Version": "2.0"}]},
        {"Target": "vacio", "Class": "os-pkgs"},
    ]
})


def test_parse_packages_lists_all_packages_not_only_vulnerable():
    pkgs = agent._parse_trivy_packages(RAW)
    assert [p["name"] for p in pkgs] == ["musl", "busybox", "flask"]
    assert pkgs[0]["layer"] == "sha256:abc" and pkgs[0]["type"] == "alpine"
    assert pkgs[2]["type"] == "pip"


def test_parse_packages_handles_empty_and_invalid_json():
    assert agent._parse_trivy_packages("") == []
    assert agent._parse_trivy_packages("no es json") == []


def test_run_trivy_asks_for_all_packages(monkeypatch):
    seen = {}

    class P:
        returncode = 0
        stdout = RAW.encode()
        stderr = b""

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return P()

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    raw, findings, err = agent.run_trivy("alpine:3.18", {})
    assert "--list-all-pkgs" in seen["cmd"] and err == ""
    assert len(findings) == 1


def test_process_job_sends_packages_for_trivy(monkeypatch):
    sent = {}
    monkeypatch.setitem(agent.SCANNERS, "trivy", lambda t, o: (RAW, [], ""))
    monkeypatch.setattr(agent, "submit_result", lambda *a, **kw: sent.update(args=a, kw=kw))
    monkeypatch.setattr(agent, "AGENT_BEHIND_DOCKER_NAT", False)
    monkeypatch.setattr(agent, "_wan_rejection", lambda s, t: None)
    agent._process_job({"id": "j1", "target": "alpine:3.18", "scanner_type": "trivy", "options": {}})
    assert sent["args"][1] == "completed"
    assert [p["name"] for p in sent["kw"]["packages"]] == ["musl", "busybox", "flask"]


def test_process_job_sends_no_packages_for_other_scanners(monkeypatch):
    sent = {}
    monkeypatch.setitem(agent.SCANNERS, "nuclei", lambda t, o: ("", [], ""))
    monkeypatch.setattr(agent, "submit_result", lambda *a, **kw: sent.update(args=a, kw=kw))
    monkeypatch.setattr(agent, "AGENT_BEHIND_DOCKER_NAT", False)
    monkeypatch.setattr(agent, "_wan_rejection", lambda s, t: None)
    agent._process_job({"id": "j2", "target": "example.com", "scanner_type": "nuclei", "options": {}})
    assert sent["kw"]["packages"] is None
