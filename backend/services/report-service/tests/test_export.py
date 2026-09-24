"""Tests de report-service/app/export.py: aplanado de datos y exportacion
a CSV/PDF. Deterministico y sin red -- toma el JSON de un reporte ya
generado (nunca inventa datos) y lo formatea."""
from app.export import _flatten, export_to_csv, export_to_pdf


class TestFlatten:
    def test_flattens_nested_dict_with_dotted_keys(self):
        rows: list[tuple[str, str]] = []
        _flatten("", {"vulns": {"critical": 3, "high": 5}}, rows)
        assert ("vulns.critical", "3") in rows
        assert ("vulns.high", "5") in rows

    def test_list_value_reports_item_count_not_contents(self):
        rows: list[tuple[str, str]] = []
        _flatten("", {"hosts": ["a", "b", "c"]}, rows)
        assert rows == [("hosts", "[3 items]")]

    def test_none_value_becomes_empty_string(self):
        rows: list[tuple[str, str]] = []
        _flatten("owner", None, rows)
        assert rows == [("owner", "")]


class TestExportToCsv:
    def test_includes_report_type_header(self):
        csv_text = export_to_csv("vulnerabilities", {"total": 10})
        assert "vulnerabilities" in csv_text
        assert "total" in csv_text
        assert "10" in csv_text

    def test_empty_data_still_produces_header_rows(self):
        csv_text = export_to_csv("executive_summary", {})
        lines = [l for l in csv_text.splitlines() if l]
        assert len(lines) >= 2  # fila de report_type + fila de encabezado field/value


class TestExportToPdf:
    def test_produces_valid_pdf_bytes(self):
        pdf_bytes = export_to_pdf("incidents", {"open": 2, "closed": 5})
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF")

    def test_handles_empty_data_without_crashing(self):
        pdf_bytes = export_to_pdf("attack_coverage", {})
        assert pdf_bytes.startswith(b"%PDF")

    def test_long_values_are_truncated_not_left_unbounded(self):
        long_value = "x" * 5000
        pdf_bytes = export_to_pdf("vulnerabilities", {"detalle": long_value})
        assert pdf_bytes.startswith(b"%PDF")  # no explota con un valor gigante
