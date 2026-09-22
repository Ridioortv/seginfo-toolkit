"""Exportadores simples de reportes generados a formatos planos (CSV). No
requiere librerias de PDF: para un export mas rico (PDF/HTML con estilos)
se puede consumir el JSON de /reports/{id} desde el frontend."""
import csv
import io


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
