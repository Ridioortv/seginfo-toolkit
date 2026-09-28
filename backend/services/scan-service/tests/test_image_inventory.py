"""Tests de app/services.py::build_image_inventory -- la logica de
agrupacion del dashboard de imagenes/paquetes de trivy. Se instancian
ScanJob directamente (sin sesion/DB real, solo el constructor de
SQLAlchemy) para poder testear la agrupacion en total aislamiento, igual
que el resto de las reglas de negocio de este paquete."""
from datetime import datetime, timezone

from app.models import ScanJob, ScanStatus, ScannerType
from app.services import build_image_inventory


def _job(target, finished_at, packages, findings=None, options=None):
    return ScanJob(
        id=f"job-{target}-{finished_at.isoformat()}",
        scanner_type=ScannerType.trivy,
        target=target,
        status=ScanStatus.completed,
        options=options or {},
        findings=findings or [],
        packages=packages,
        finished_at=finished_at,
    )


class TestBuildImageInventory:
    def test_single_scan_becomes_one_image(self):
        job = _job(
            "alpine:3.18",
            datetime(2026, 9, 1, tzinfo=timezone.utc),
            [{"name": "musl", "version": "1.2.4"}],
        )
        images = build_image_inventory([job])
        assert len(images) == 1
        assert images[0]["target"] == "alpine:3.18"
        assert images[0]["package_count"] == 1

    def test_rescanning_same_target_keeps_only_the_most_recent(self):
        # jobs YA vienen ordenados desc por finished_at (ver docstring de
        # build_image_inventory) -- el mas nuevo primero.
        newer = _job("alpine:3.18", datetime(2026, 9, 20, tzinfo=timezone.utc), [{"name": "musl", "version": "1.2.5"}])
        older = _job("alpine:3.18", datetime(2026, 9, 1, tzinfo=timezone.utc), [{"name": "musl", "version": "1.2.4"}])
        images = build_image_inventory([newer, older])
        assert len(images) == 1
        assert images[0]["packages"][0]["version"] == "1.2.5"

    def test_jobs_without_packages_are_skipped(self):
        # Escaneo hecho antes de --list-all-pkgs (o algo raro): findings
        # puede tener datos pero packages queda vacio -- no debe aparecer.
        job = _job("viejo:1.0", datetime(2026, 9, 1, tzinfo=timezone.utc), [], findings=[{"severity": "high"}])
        assert build_image_inventory([job]) == []

    def test_different_targets_are_separate_images(self):
        a = _job("alpine:3.18", datetime(2026, 9, 1, tzinfo=timezone.utc), [{"name": "musl", "version": "1"}])
        b = _job("ubuntu:22.04", datetime(2026, 9, 2, tzinfo=timezone.utc), [{"name": "libc6", "version": "1"}])
        images = build_image_inventory([b, a])
        targets = {i["target"] for i in images}
        assert targets == {"alpine:3.18", "ubuntu:22.04"}

    def test_vulnerabilities_are_counted_by_severity(self):
        job = _job(
            "alpine:3.18",
            datetime(2026, 9, 1, tzinfo=timezone.utc),
            [{"name": "musl", "version": "1"}],
            findings=[{"severity": "critical"}, {"severity": "critical"}, {"severity": "low"}],
        )
        images = build_image_inventory([job])
        assert images[0]["vulnerability_count"] == 3
        assert images[0]["vulnerabilities_by_severity"] == {"critical": 2, "low": 1}

    def test_mode_comes_from_options_and_defaults_to_image(self):
        con_mode = _job("archivo.tar", datetime(2026, 9, 1, tzinfo=timezone.utc), [{"name": "x", "version": "1"}], options={"mode": "upload"})
        sin_mode = _job("alpine:3.18", datetime(2026, 9, 2, tzinfo=timezone.utc), [{"name": "x", "version": "1"}])
        images = {i["target"]: i for i in build_image_inventory([con_mode, sin_mode])}
        assert images["archivo.tar"]["mode"] == "upload"
        assert images["alpine:3.18"]["mode"] == "image"

    def test_results_sorted_most_recent_first(self):
        old = _job("a", datetime(2026, 9, 1, tzinfo=timezone.utc), [{"name": "x", "version": "1"}])
        new = _job("b", datetime(2026, 9, 10, tzinfo=timezone.utc), [{"name": "y", "version": "1"}])
        images = build_image_inventory([old, new])
        assert [i["target"] for i in images] == ["b", "a"]

    def test_empty_input_returns_empty(self):
        assert build_image_inventory([]) == []
