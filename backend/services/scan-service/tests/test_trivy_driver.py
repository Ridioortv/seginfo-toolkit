"""Tests para app/scanners/trivy.py -- construccion de comando y parseo de
JSON, sin ejecutar trivy de verdad."""
import json
from app.scanners.trivy import _build_trivy_cmd, _parse_trivy_json, _parse_trivy_packages

_SAMPLE_JSON = json.dumps({
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.4)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "Title": "openssl: buffer overflow",
                    "Severity": "CRITICAL",
                    "InstalledVersion": "3.0.1",
                    "FixedVersion": "3.0.2",
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "libc",
                    "Description": "desc sin title",
                    "Severity": "UNKNOWN",
                    "InstalledVersion": "1.0",
                    "FixedVersion": None,
                },
            ],
        }
    ]
})

_SAMPLE_JSON_WITH_PACKAGES = json.dumps({
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.4)",
            "Type": "alpine",
            "Packages": [
                {"Name": "openssl", "Version": "3.0.1", "Arch": "x86_64"},
                {"Name": "musl", "Version": "1.2.4-r0", "Arch": "x86_64"},
            ],
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "Severity": "CRITICAL",
                    "InstalledVersion": "3.0.1",
                },
            ],
        }
    ]
})


def test_build_cmd_defaults_to_image_mode_with_skip_flags():
    cmd = _build_trivy_cmd("alpine:3.18", {}, cache_dir="/root/.cache/trivy")
    assert cmd[0:2] == ["trivy", "image"]
    assert "--skip-db-update" in cmd
    assert "--skip-java-db-update" in cmd
    assert "--cache-dir" in cmd and "/root/.cache/trivy" in cmd
    assert cmd[-1] == "alpine:3.18"


def test_build_cmd_fs_mode():
    cmd = _build_trivy_cmd("/src", {"mode": "fs"}, cache_dir="/cache")
    assert cmd[0:2] == ["trivy", "fs"]
    assert cmd[-1] == "/src"


def test_parse_trivy_json_extracts_findings():
    findings = _parse_trivy_json(_SAMPLE_JSON)
    assert len(findings) == 2
    critical = next(f for f in findings if f["cve_id"] == "CVE-2024-1234")
    assert critical["severity"] == "critical"
    assert critical["package"] == "openssl"
    assert "openssl" in critical["title"]


def test_parse_trivy_json_unknown_severity_maps_to_info():
    findings = _parse_trivy_json(_SAMPLE_JSON)
    unknown = next(f for f in findings if f["cve_id"] == "CVE-2024-5678")
    assert unknown["severity"] == "info"
    assert "desc sin title" in unknown["description"]


def test_parse_trivy_json_malformed_returns_empty():
    assert _parse_trivy_json("no es json <<<") == []


def test_parse_trivy_json_empty_string_returns_empty():
    assert _parse_trivy_json("") == []


def test_build_cmd_includes_list_all_pkgs():
    cmd = _build_trivy_cmd("alpine:3.18", {}, cache_dir="/root/.cache/trivy")
    assert "--list-all-pkgs" in cmd
    # el target SIEMPRE tiene que quedar ultimo (varios callers hacen
    # `[c for c in cmd if c not in (...)]` para el fallback de DB vacia --
    # ver TrivyDriver.run -- y eso solo funciona si el target no se puede
    # confundir con un flag).
    assert cmd[-1] == "alpine:3.18"


def test_parse_trivy_packages_extracts_all_packages_not_just_vulnerable():
    packages = _parse_trivy_packages(_SAMPLE_JSON_WITH_PACKAGES)
    assert len(packages) == 2
    names = {p["name"] for p in packages}
    assert names == {"openssl", "musl"}
    musl = next(p for p in packages if p["name"] == "musl")
    assert musl["version"] == "1.2.4-r0"
    assert musl["type"] == "alpine"
    assert musl["target"].startswith("alpine:3.18")


def test_parse_trivy_packages_without_list_all_pkgs_returns_empty():
    # _SAMPLE_JSON (el de arriba) no tiene "Packages" -- simula un escaneo
    # viejo hecho ANTES de que existiera --list-all-pkgs.
    assert _parse_trivy_packages(_SAMPLE_JSON) == []


def test_parse_trivy_packages_malformed_returns_empty():
    assert _parse_trivy_packages("no es json <<<") == []


def test_parse_trivy_packages_skips_entries_without_name():
    raw = json.dumps({"Results": [{"Target": "x", "Packages": [{"Version": "1.0"}]}]})
    assert _parse_trivy_packages(raw) == []
