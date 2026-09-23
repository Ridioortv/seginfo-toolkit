"""Exportadores de reportes generados: CSV plano y PDF con estilos
(reportlab, sin dependencias de sistema como cairo/pango -- corre bien en
la imagen Debian "slim" del contenedor)."""
import csv
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

_REPORT_TITLES = {
    "executive_summary": "Resumen ejecutivo",
    "vulnerabilities": "Vulnerabilidades",
    "incidents": "Incidentes",
    "attack_coverage": "Cobertura ATT&CK",
}


def _flatten(prefix: str, value, rows: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, rows)
    elif isinstance(value, list):
        rows.append((prefix, f"[{len(value)} items]"))
    else:
        rows.append((prefix, "" if value is None else str(value)))


def export_to_csv(report_type: str, data: dict) -> str:
    rows: list[tuple[str, str]] = []
    _flatten("", data, rows)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["report_type", report_type])
    writer.writerow(["field", "value"])
    for field, value in rows:
        writer.writerow([field, value])
    return buffer.getvalue()


def export_to_pdf(report_type: str, data: dict) -> bytes:
    """Genera un PDF simple (titulo, fecha, tabla campo/valor -- mismo
    aplanado que usa el CSV) a partir del JSON del reporte. Pensado para
    adjuntarse a un email (ver report-service scheduled reports) o para
    descargarse desde /reports/{id}/export?format=pdf."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()

    title = _REPORT_TITLES.get(report_type, report_type)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows: list[tuple[str, str]] = []
    _flatten("", data, rows)

    table_data = [["Campo", "Valor"]] + [
        [field or "-", (value[:300] if len(value) > 300 else value) or "-"] for field, value in rows
    ]
    table = Table(table_data, colWidths=[7 * cm, 10 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story = [
        Paragraph(f"SentinelOps -- {title}", styles["Title"]),
        Paragraph(f"Generado: {generated_at}", styles["Normal"]),
        Spacer(1, 0.5 * cm),
        table,
    ]
    doc.build(story)
    return buffer.getvalue()
