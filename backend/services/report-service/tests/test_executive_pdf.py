"""Informe ejecutivo en PDF: se arma desde el atestado firmado, sin recalcular, con marca propia opcional."""
import base64
import io
import struct
import zlib

from app import executive_pdf as ep


def png(w=40, h=20, rgb=(200, 30, 30)) -> str:
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    return "data:image/png;base64," + base64.b64encode(data).decode()


def attestation(status="attention", with_data=True):
    d = lambda c, p: {"current": c, "previous": p, "change": None if c is None or p is None else c - p, "change_pct": None}
    body = {
        "organization": {"id": "o1", "name": "Acme <SA> & Cia"}, "generated_at": "2026-06-30T12:00:00+00:00", "days": 30,
        "period": {"from": "2026-05-31T12:00:00+00:00", "to": "2026-06-30T12:00:00+00:00"},
        "previous_period": {"from": "2026-05-01T12:00:00+00:00", "to": "2026-05-31T12:00:00+00:00"}, "status": status,
        "attention": [{"level": "critical", "code": "kev_open", "message": {"text": "{0} vulnerabilidades abiertas se explotan.", "args": ["2"]}, "link": ""},
                      {"level": "info", "code": "x", "message": {"text": "Texto con <tags> & simbolos", "args": []}, "link": ""}],
        "sources": {"asset-service": {"ok": False, "error": "HTTP 502"}}, "limits": ["Limite uno.", "Limite dos."],
        "meaning": "Prueba que TERO calculo estos indicadores.", "custody": {"ok": True, "entries": 7},
        "trend": [{"day": f"2026-06-{i:02d}", "critical_high": 10 - i // 3, "compliance": 40 + i, "mttr_real_hours": None, "exposure": 50 + i} for i in range(1, 12)],
    }
    if with_data:
        body.update(
            vulnerabilities={"critical_high": 4, "kev": 2, "oldest_critical_high_days": 95, "created_critical_high": d(4, 1), "remediated_critical_high": d(1, 2)},
            remediation={"mttr_declared_hours": 24, "mttr_real_hours": 120, "false_closure_rate_pct": 25.0},
            compliance={"score_verified": 40.0, "previous_score_verified": 52.0, "change": -12.0},
            cases={"open": 3, "overdue": 1, "mttr_hours": d(30.0, 40.0)}, exceptions={"active": 2}, vendors={"high_or_critical_risk": 1},
            drills={"completed_total": 1, "last_score": 85},
            exposure={"weights": {"critical": 10, "high": 5}, "by_business_unit": [
                {"unit": "Finanzas", "assets": 3, "critical": 1, "high": 0, "kev": 1, "score": 15.0, "share_pct": 75.0},
                {"unit": "(sin unidad asignada)", "assets": 1, "critical": 0, "high": 1, "kev": 0, "score": 5.0, "share_pct": 25.0}],
                "top_assets": [{"hostname": "erp", "business_unit": "Finanzas", "critical": 1, "high": 0, "score": 15.0}]})
    return {"format": "tero-attestation", "version": 1, "kind": "executive", "organization_id": "o1", "generated_at": "2026-06-30T12:00:00Z",
            "body": body, "public_key": "ab" * 32, "key_fingerprint": "aaaa-bbbb", "signature": "cd" * 64}


def test_fmt_msg_fills_placeholders():
    assert ep.fmt_msg({"text": "{0} de {1} cosas", "args": ["2", "5"]}) == "2 de 5 cosas"


def test_pdf_is_generated_and_escapes_untrusted_text():
    pdf = ep.build_pdf(attestation())
    assert pdf.startswith(b"%PDF") and len(pdf) > 3000


def test_pdf_with_missing_sections_and_each_status():
    for st in ("stable", "watch", "attention", "desconocido"):
        assert ep.build_pdf(attestation(st, with_data=False)).startswith(b"%PDF")


def test_brand_color_and_logo_are_validated():
    assert ep._color("#112233") == "#112233" and ep._color("rojo; DROP") == ep.DEFAULT_COLOR and ep._color(None) == ep.DEFAULT_COLOR
    assert ep._logo(png()) is not None
    assert ep._logo("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=") is None      # SVG no: puede traer scripts
    assert ep._logo("data:image/png;base64,@@@") is None and ep._logo(None) is None
    assert ep.build_pdf(attestation(), {"name": "Mi MSSP", "color": "#0a7", "logo": png()}).startswith(b"%PDF")  # color invalido -> default
    assert ep.build_pdf(attestation(), {"name": "Mi MSSP", "color": "#0a7a55", "logo": png()}).startswith(b"%PDF")
