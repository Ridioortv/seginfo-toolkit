"""Informe ejecutivo para la direccion en PDF (reportlab), a partir del atestado firmado de case-service.

El PDF NO recalcula nada: muestra exactamente el cuerpo que case-service firmo (Ed25519), con la huella de la clave, el
hash del contenido y como verificarlo. Asi lo que se lee en papel coincide con lo que se puede comprobar sin TERO.
Marca propia opcional (`brand`): nombre, color y logo del cliente/partner; si falta, se usa la de TERO."""
from __future__ import annotations

import base64
import io
import re
from datetime import datetime

from reportlab.graphics.shapes import Drawing, Line, PolyLine, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

DEFAULT_COLOR = "#1f4e79"
STATUS_TEXT = {"stable": ("ESTABLE", "#15803d", "Sin alertas que requieran decision de la direccion."),
               "watch": ("A VIGILAR", "#b45309", "Hay puntos que conviene atender en el corto plazo."),
               "attention": ("REQUIERE ATENCION", "#b91c1c", "Hay puntos criticos que necesitan una decision.")}
LEVEL_TEXT = {"critical": ("Critico", "#b91c1c"), "warning": ("Atencion", "#b45309"), "info": ("Informativo", "#475569")}
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
_DATA_URI = re.compile(r"^data:image/(png|jpeg);base64,([A-Za-z0-9+/=]+)$")


def fmt_msg(msg: dict) -> str:
    text = msg.get("text", "")
    for i, a in enumerate(msg.get("args", [])):
        text = text.replace("{%d}" % i, str(a))
    return text


def _num(v, suffix="", dash="-"):
    if v is None:
        return dash
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return f"{v}{suffix}"


def _change(d: dict, good_down: bool = True) -> str:
    """Texto del cambio contra el periodo anterior: '+3 (+25%)'."""
    if not d or d.get("change") is None:
        return "sin comparacion"
    ch = d["change"]
    ch = int(ch) if float(ch).is_integer() else ch
    pct = f" ({d['change_pct']:+g}%)" if d.get("change_pct") is not None else ""
    return f"{ch:+g}{pct}" if not isinstance(ch, int) else f"{ch:+d}{pct}"


def _color(value: str | None) -> str:
    return value if value and _HEX.match(value) else DEFAULT_COLOR


def _logo(data_uri: str | None):
    m = _DATA_URI.match(data_uri or "")
    if not m or len(data_uri) > 400_000:
        return None
    try:
        raw = base64.b64decode(m.group(2), validate=True)
        w, h = ImageReader(io.BytesIO(raw)).getSize()
    except Exception:
        return None
    height = 1.4 * cm
    return Image(io.BytesIO(raw), width=height * w / h, height=height)


def _trend_chart(rows: list[dict], key: str, title: str, color: str) -> Drawing | None:
    pts = [(i, r[key]) for i, r in enumerate(rows) if r.get(key) is not None]
    if len(pts) < 2:
        return None
    w, h, pad = 8.2 * cm, 3.6 * cm, 0.5 * cm
    ys = [p[1] for p in pts]
    lo, hi = min(ys + [0]), max(ys)
    span = (hi - lo) or 1
    n = max(len(rows) - 1, 1)
    d = Drawing(w, h + 0.6 * cm)
    d.add(String(0, h + 0.2 * cm, title, fontName="Helvetica-Bold", fontSize=8))
    d.add(Line(pad, pad, w, pad, strokeColor=colors.HexColor("#9ca3af"), strokeWidth=0.5))
    flat = []
    for i, v in pts:
        flat += [pad + (w - pad) * i / n, pad + (h - 2 * pad) * (v - lo) / span]
    d.add(PolyLine(flat, strokeColor=colors.HexColor(color), strokeWidth=1.6))
    d.add(String(pad, 0, rows[0]["day"], fontSize=6))
    d.add(String(w - 1.6 * cm, 0, rows[-1]["day"], fontSize=6))
    d.add(String(w - 0.3 * cm, pad + (h - 2 * pad) * (ys[-1] - lo) / span + 3, _num(ys[-1]), fontSize=7, textAnchor="end"))
    return d


def build_pdf(doc: dict, brand: dict | None = None) -> bytes:
    body = doc["body"]
    brand = brand or {}
    accent = _color(brand.get("color"))
    org = (body.get("organization") or {}).get("name") or "Organizacion"
    brand_name = brand.get("name") or "TERO Security"
    st = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=st["Title"], fontSize=22, textColor=colors.HexColor(accent), alignment=0, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=st["Heading2"], fontSize=13, textColor=colors.HexColor(accent), spaceBefore=12, spaceAfter=4)
    small = ParagraphStyle("small", parent=st["Normal"], fontSize=7.5, leading=10, textColor=colors.HexColor("#475569"))
    normal = ParagraphStyle("n", parent=st["Normal"], fontSize=9, leading=12)
    cell = ParagraphStyle("c", parent=normal, fontSize=8, leading=10)

    def esc(t) -> str:
        return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def table(data, widths, header=True):
        t = Table([[Paragraph(esc(c), cell) if not hasattr(c, "wrap") else c for c in row] for row in data], colWidths=widths, repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")])]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(accent)), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
        t.setStyle(TableStyle(style))
        return t

    def head(data):  # encabezado en blanco sobre fondo de color
        return [Paragraph(f'<font color="white"><b>{esc(c)}</b></font>', cell) for c in data]

    story: list = []
    logo = _logo(brand.get("logo"))
    top = [[logo or Paragraph(f"<b>{esc(brand_name)}</b>", normal),
            Paragraph(f"Informe ejecutivo de seguridad<br/>{esc(body['generated_at'][:10])}", ParagraphStyle("r", parent=normal, alignment=2))]]
    story.append(Table(top, colWidths=[9 * cm, 8 * cm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(esc(org), h1))
    story.append(Spacer(1, 0.2 * cm))
    p, pp = body["period"], body["previous_period"]
    story.append(Paragraph(f"Periodo: {esc(p['from'][:10])} a {esc(p['to'][:10])} ({body['days']} dias). "
                           f"Comparado con {esc(pp['from'][:10])} a {esc(pp['to'][:10])}.", small))
    label, color, text = STATUS_TEXT.get(body["status"], STATUS_TEXT["watch"])
    story.append(Spacer(1, 0.3 * cm))
    story.append(Table([[Paragraph(f'<font color="white"><b>{label}</b></font>', ParagraphStyle("b", parent=normal, fontSize=12, alignment=1)),
                         Paragraph(esc(text), normal)]], colWidths=[4.2 * cm, 12.8 * cm],
                       style=[("BACKGROUND", (0, 0), (0, 0), colors.HexColor(color)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(color)), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))

    # --- que requiere atencion
    story.append(Paragraph("Que requiere atencion", h2))
    attn = body.get("attention") or []
    if attn:
        rows = [head(["Nivel", "Detalle"])]
        for a in attn:
            lv, c = LEVEL_TEXT.get(a["level"], LEVEL_TEXT["info"])
            rows.append([Paragraph(f'<font color="{c}"><b>{lv}</b></font>', cell), Paragraph(esc(fmt_msg(a["message"])), cell)])
        story.append(table(rows, [2.6 * cm, 14.4 * cm]))
    else:
        story.append(Paragraph("Nada que requiera una decision en este periodo.", normal))

    # --- indicadores
    story.append(Paragraph("Indicadores clave", h2))
    k = [head(["Indicador", "Actual", "Periodo anterior", "Cambio"])]
    v, r, c, ca = (body.get(x) for x in ("vulnerabilities", "remediation", "compliance", "cases"))
    if v:
        k += [["Vulnerabilidades abiertas (criticas + altas)", _num(v["critical_high"]), "", ""],
              ["Explotadas activamente (KEV) abiertas", _num(v["kev"]), "", ""],
              ["Criticas o altas nuevas", _num(v["created_critical_high"]["current"]), _num(v["created_critical_high"]["previous"]), _change(v["created_critical_high"])],
              ["Criticas o altas corregidas", _num(v["remediated_critical_high"]["current"]), _num(v["remediated_critical_high"]["previous"]), _change(v["remediated_critical_high"])],
              ["Antiguedad de la critica/alta mas vieja (dias)", _num(v["oldest_critical_high_days"]), "", ""]]
    if r:
        k += [["Tiempo de correccion DECLARADO (horas)", _num(r["mttr_declared_hours"]), "", ""],
              ["Tiempo de correccion REAL, con cierre verificado (horas)", _num(r["mttr_real_hours"]), "", ""],
              ["Cierres declarados que no pasaron la verificacion", _num(r["false_closure_rate_pct"], "%"), "", ""]]
    if c and c.get("score_verified") is not None:
        k.append(["Cumplimiento verificado (de 100)", _num(c["score_verified"]), _num(c.get("previous_score_verified")), _num(c.get("change")) if c.get("change") is not None else "sin comparacion"])
    if ca:
        k += [["Casos abiertos / fuera de plazo", f"{ca['open']} / {ca['overdue']}", "", ""],
              ["Tiempo medio de resolucion de casos (horas)", _num(ca["mttr_hours"]["current"]), _num(ca["mttr_hours"]["previous"]), _change(ca["mttr_hours"])]]
    for key, label2, field in (("exceptions", "Excepciones de riesgo vigentes", "active"), ("vendors", "Proveedores con riesgo alto o critico", "high_or_critical_risk")):
        if body.get(key):
            k.append([label2, _num(body[key][field]), "", ""])
    if body.get("drills"):
        d = body["drills"]
        k.append(["Simulacros de respuesta completados (ultimo puntaje)", f"{d['completed_total']} ({_num(d['last_score'])})", "", ""])
    story.append(table(k, [8.4 * cm, 2.8 * cm, 3 * cm, 2.8 * cm]))
    if r and r.get("mttr_real_hours") is not None and r.get("mttr_declared_hours") is not None:
        story.append(Spacer(1, 0.15 * cm))
        story.append(Paragraph("El tiempo declarado llega hasta que alguien marca la vulnerabilidad como corregida; el real, hasta que TERO "
                               "comprueba con un nuevo escaneo que ya no esta. La diferencia es el tiempo que el riesgo siguio abierto sin que se supiera.", small))

    # --- exposicion por unidad de negocio
    x = body.get("exposure")
    if x and x["by_business_unit"]:
        story.append(Paragraph("Exposicion por unidad de negocio", h2))
        rows = [head(["Unidad", "Activos", "Criticas", "Altas", "KEV", "Exposicion", "% del total"])]
        for u in x["by_business_unit"]:
            rows.append([u["unit"], _num(u["assets"]), _num(u["critical"]), _num(u["high"]), _num(u["kev"]), _num(u["score"]), _num(u["share_pct"], "%")])
        story.append(table(rows, [5.2 * cm, 1.8 * cm, 1.8 * cm, 1.8 * cm, 1.4 * cm, 2.4 * cm, 2.6 * cm]))
        w = x.get("weights") or {}
        story.append(Paragraph("Exposicion = abiertas ponderadas (" + ", ".join(f"{k2} {v2}" for k2, v2 in w.items()) +
                               "; x1,5 si se explota activamente). Es una ayuda para priorizar, no una medida de perdida economica.", small))
        if x.get("top_assets"):
            story.append(Paragraph("Activos con mayor exposicion", h2))
            rows = [head(["Activo", "Unidad", "Criticas", "Altas", "Exposicion"])]
            for a in x["top_assets"][:8]:
                rows.append([a["hostname"] or "(sin activo asociado)", a["business_unit"], _num(a["critical"]), _num(a["high"]), _num(a["score"])])
            story.append(table(rows, [5.4 * cm, 5 * cm, 2 * cm, 2 * cm, 2.6 * cm]))

    # --- tendencia
    trend = body.get("trend") or []
    charts = [c2 for c2 in (_trend_chart(trend, "critical_high", "Criticas + altas abiertas", accent),
                            _trend_chart(trend, "compliance", "Cumplimiento verificado", "#15803d"),
                            _trend_chart(trend, "mttr_real_hours", "Tiempo real de correccion (h)", "#b45309"),
                            _trend_chart(trend, "exposure", "Exposicion total", "#b91c1c")) if c2 is not None]
    if charts:
        rows = [charts[i:i + 2] + [""] * (2 - len(charts[i:i + 2])) for i in range(0, len(charts), 2)]
        story.append(KeepTogether([Paragraph("Tendencia", h2), Table(rows, colWidths=[8.5 * cm, 8.5 * cm])]))
    else:
        story.append(Paragraph("Tendencia", h2))
        story.append(Paragraph("Todavia no hay suficientes fotos diarias para dibujar la evolucion (TERO guarda una por dia).", normal))

    # --- fuentes sin datos
    down = [n for n, s in (body.get("sources") or {}).items() if not s.get("ok")]
    if down:
        story.append(Paragraph("Fuentes sin datos", h2))
        story.append(Paragraph("No se pudo leer: " + esc(", ".join(down)) + ". Esas secciones faltan; no se completaron con ceros.", normal))

    # --- firma y verificacion
    story.append(KeepTogether([
        Paragraph("Firma y verificacion", h2),
        Paragraph(esc(body.get("meaning", "")), normal), Spacer(1, 0.2 * cm),
        table([["Generado", esc(doc["generated_at"])], ["Huella de la clave de firma", esc(doc.get("key_fingerprint", ""))],
               ["Firma (Ed25519, inicio)", esc(doc["signature"][:48] + "...")],
               ["Cadena de custodia", ("integra, " if (body.get("custody") or {}).get("ok") else "CON PROBLEMAS, ") + f"{(body.get('custody') or {}).get('entries', '?')} registros"]],
              [5 * cm, 12 * cm], header=False),
        Spacer(1, 0.2 * cm),
        Paragraph("Para comprobarlo sin TERO: guarde el archivo informe-ejecutivo.json junto a este PDF y ejecute "
                  "<font face='Courier'>python verificar_evidencia.py informe-ejecutivo.json</font>. Si algun numero se modifico, "
                  "la verificacion falla. Compare la huella con la que le informo su proveedor de TERO.", small),
        Spacer(1, 0.2 * cm),
        Paragraph("Limites: " + esc(" ".join(body.get("limits", []))), small),
    ]))

    buf = io.BytesIO()

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(2 * cm, 1.2 * cm, f"{brand_name} - Informe ejecutivo - {org}")
        canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Pagina {d.page}")
        canvas.setFillColor(colors.HexColor(accent))
        canvas.rect(0, A4[1] - 0.35 * cm, A4[0], 0.35 * cm, stroke=0, fill=1)
        canvas.restoreState()

    SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.6 * cm, bottomMargin=2 * cm,
                      title=f"Informe ejecutivo - {org}", author=brand_name).build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
