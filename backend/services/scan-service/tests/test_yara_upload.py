"""Tests de la subida de archivos para YARA (POST /scans/upload-yara):
la logica pura que limpia el path temporal de los resultados, y que
execute_scan_job le pasa al driver el path temporal real (no el nombre
para mostrar) y borra la carpeta de subida al terminar."""
import asyncio
import os
import tempfile
from types import SimpleNamespace

from app import services
from app.scanners.base import ScanResult


def test_strip_upload_dir_removes_temp_prefix_from_findings_and_raw_output():
    upload_dir = "/tmp/yara-upload-ab12cd"
    result = ScanResult(
        raw_output=f"SentinelOps_EICAR_Test_File {upload_dir}/eicar.txt\n",
        findings=[
            {
                "title": f"YARA: SentinelOps_EICAR_Test_File en {upload_dir}/eicar.txt",
                "description": f"El archivo '{upload_dir}/eicar.txt' coincide con la regla.",
                "file_path": f"{upload_dir}/eicar.txt",
                "severity": "info",
                "cve_id": None,
            }
        ],
    )

    services.strip_upload_dir(result, upload_dir)

    assert result.raw_output == "SentinelOps_EICAR_Test_File eicar.txt\n"
    finding = result.findings[0]
    assert finding["file_path"] == "eicar.txt"
    assert finding["title"] == "YARA: SentinelOps_EICAR_Test_File en eicar.txt"
    assert "/tmp/" not in finding["description"]
    assert finding["severity"] == "info"
    assert finding["cve_id"] is None


def test_strip_upload_dir_handles_trailing_slash_and_empty_result():
    result = ScanResult(raw_output="", findings=[])
    services.strip_upload_dir(result, "/tmp/yara-upload-xyz/")
    assert result.raw_output == ""
    assert result.findings == []


def test_strip_upload_dir_keeps_subdirectory_structure_for_multi_file_uploads():
    upload_dir = "/tmp/yara-upload-multi"
    result = ScanResult(
        raw_output="",
        findings=[{"file_path": f"{upload_dir}/a.php", "title": f"x en {upload_dir}/a.php"}],
    )
    services.strip_upload_dir(result, upload_dir)
    assert result.findings[0]["file_path"] == "a.php"


class _FakeJob:
    def __init__(self, target):
        self.id = "job-1"
        self.scanner_type = services.ScannerType.yara
        self.target = target
        self.options = {"mode": "upload"}
        self.status = services.ScanStatus.pending
        self.asset_id = None
        self.error_message = None
        self.raw_result = None
        self.findings = []
        self.packages = []
        self.started_at = None
        self.finished_at = None


class _FakeSession:
    def __init__(self, job):
        self._job = job

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, _model, _job_id):
        return self._job

    async def commit(self):
        return None


def test_execute_scan_job_uses_target_override_and_deletes_upload_dir(monkeypatch):
    upload_dir = tempfile.mkdtemp(prefix="yara-upload-test-")
    real_file = os.path.join(upload_dir, "malo.php")
    with open(real_file, "w") as fh:
        fh.write("x")
    job = _FakeJob(target="malo.php")  # lo que ve el usuario, NO un path real
    seen = {}

    class _FakeDriver:
        binary_name = "yara"

        def is_available(self):
            return True

        async def run(self, target, options):
            seen["target"] = target
            return ScanResult(
                raw_output=f"R {target}\n",
                findings=[{"title": f"en {target}", "file_path": target, "severity": "high"}],
            )

    monkeypatch.setattr(services, "get_driver", lambda _t: _FakeDriver())

    async def _noop(_job):
        return None

    monkeypatch.setattr(services, "_forward_findings_to_vuln_service", _noop)
    monkeypatch.setattr(services, "_forward_findings_to_siem_service", _noop)

    asyncio.run(
        services.execute_scan_job(
            lambda: _FakeSession(job), job.id, target_override=real_file, cleanup_dir=upload_dir
        )
    )

    assert seen["target"] == real_file  # el driver recibio el path temporal real
    assert job.status == services.ScanStatus.completed
    assert job.findings[0]["file_path"] == "malo.php"  # y el usuario ve solo el nombre
    assert upload_dir not in job.raw_result
    assert not os.path.exists(upload_dir)  # la carpeta de subida se borro


def test_execute_scan_job_without_override_keeps_old_behavior(monkeypatch):
    job = _FakeJob(target="alpine:3.18")
    seen = {}

    class _FakeDriver:
        binary_name = "yara"

        def is_available(self):
            return True

        async def run(self, target, options):
            seen["target"] = target
            return ScanResult(raw_output="", findings=[])

    monkeypatch.setattr(services, "get_driver", lambda _t: _FakeDriver())
    asyncio.run(services.execute_scan_job(lambda: _FakeSession(job), job.id))

    assert seen["target"] == "alpine:3.18"
    assert job.status == services.ScanStatus.completed
