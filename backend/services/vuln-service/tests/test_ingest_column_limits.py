"""Regression: POST /vulnerabilities/ingest devolvia 500 con hallazgos de ZAP
y se perdia el lote completo.

ZAP manda en `service` hasta 5 URLs unidas por coma (varios cientos de
caracteres) y la columna `vulnerabilities.service` es VARCHAR(100). Postgres
rechaza el INSERT (DataError) -> 500 -> scan-service, que no mira la
respuesta, dejaba el escaneo "completed" con N hallazgos pero sin ningun
registro en vuln-service ("Este escaneo no encontro hallazgos" en la UI).

SQLite (el de los tests) no hace cumplir el largo del VARCHAR, asi que este
test comprueba directamente que lo que se intenta guardar ya entra en cada
columna, sin necesitar Postgres.
"""
import asyncio
from types import SimpleNamespace

import app.services as svc
from app.models import Vulnerability
from app.schemas import FindingIn, IngestRequest


class _FakeResult:
    def scalar_one_or_none(self):
        return None


class _FakeDb:
    def __init__(self):
        self.added: list[Vulnerability] = []

    async def execute(self, _query):
        return _FakeResult()

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass


def _limit(column_name: str) -> int:
    return Vulnerability.__table__.c[column_name].type.length


def _ingest(findings, scanner_type="zap", scan_job_id="job-1"):
    db = _FakeDb()
    payload = IngestRequest(scan_job_id=scan_job_id, scanner_type=scanner_type, findings=findings)
    created, updated = asyncio.run(svc.ingest_findings(db, payload, "org-1"))
    return db, created, updated


def test_zap_style_long_service_field_fits_the_column():
    urls = ", ".join(f"https://scanme.example.org/some/long/path/segment/{i}/index.html?x=1" for i in range(5))
    assert len(urls) > 100
    db, created, _ = _ingest([FindingIn(title="Missing Anti-clickjacking Header", severity="medium", service=urls)])
    assert created == 1
    assert len(db.added[0].service) <= _limit("service")


def test_every_text_column_is_clipped_to_its_limit():
    long = "x" * 2000
    db, created, _ = _ingest(
        [
            FindingIn(
                title=long,
                cve_id="CVE-2026-" + "9" * 100,
                package=long,
                installed_version=long,
                fixed_version=long,
                service=long,
                severity="high",
            )
        ]
    )
    assert created == 1
    v = db.added[0]
    for col in ("title", "cve_id", "package", "installed_version", "fixed_version", "service", "source_scanner"):
        assert len(getattr(v, col)) <= _limit(col), col


def test_short_values_are_stored_unchanged():
    db, _, _ = _ingest([FindingIn(title="Open redirect", service="https://a.example", package="openssl")])
    v = db.added[0]
    assert (v.title, v.service, v.package) == ("Open redirect", "https://a.example", "openssl")


def test_out_of_range_port_is_dropped_not_stored():
    db, _, _ = _ingest([FindingIn(title="a", port=99999999999), FindingIn(title="b", port=443)])
    assert [v.port for v in db.added] == [None, 443]


def test_scanner_type_schema_cap_matches_the_column():
    assert IngestRequest.model_fields["scanner_type"].metadata[0].max_length <= _limit("source_scanner")
