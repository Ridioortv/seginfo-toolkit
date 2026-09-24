"""Tests para app/remediation.py::build_remediation_steps -- funcion pura,
sin DB ni red, igual que test_priority_score.py en este mismo paquete."""
from dataclasses import dataclass

from app.remediation import build_remediation_steps


@dataclass
class _FakeVuln:
    cve_id: str | None = None
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    port: int | None = None
    service: str = ""
    is_kev: bool = False
    severity: str = "medium"


class TestBuildRemediationSteps:
    def test_package_with_fixed_version_suggests_upgrade(self):
        vuln = _FakeVuln(package="openssl", installed_version="1.1.1", fixed_version="1.1.1w")
        steps = build_remediation_steps(vuln)
        assert any("openssl" in s and "1.1.1w" in s for s in steps)

    def test_package_without_fixed_version_suggests_checking_for_update(self):
        vuln = _FakeVuln(package="openssl", installed_version="1.1.1")
        steps = build_remediation_steps(vuln)
        assert any("openssl" in s and "version mas nueva" in s for s in steps)

    def test_open_port_suggests_closing_or_restricting(self):
        vuln = _FakeVuln(port=23, service="telnet")
        steps = build_remediation_steps(vuln)
        assert any("23" in s and "telnet" in s for s in steps)

    def test_cve_suggests_reviewing_the_advisory(self):
        vuln = _FakeVuln(cve_id="CVE-2024-12345")
        steps = build_remediation_steps(vuln)
        assert any("CVE-2024-12345" in s for s in steps)

    def test_kev_finding_gets_top_priority_step_first(self):
        vuln = _FakeVuln(cve_id="CVE-2024-12345", is_kev=True)
        steps = build_remediation_steps(vuln)
        assert "KEV" in steps[0]

    def test_no_data_still_returns_a_generic_step_and_the_rescan_reminder(self):
        vuln = _FakeVuln()
        steps = build_remediation_steps(vuln)
        assert len(steps) >= 2
        assert any("hardening" in s for s in steps)
        assert any("volver a escanear" in s for s in steps)

    def test_rescan_reminder_is_always_the_last_step(self):
        vuln = _FakeVuln(package="openssl", fixed_version="1.1.1w", port=443, cve_id="CVE-2024-1", is_kev=True)
        steps = build_remediation_steps(vuln)
        assert "volver a escanear" in steps[-1]
