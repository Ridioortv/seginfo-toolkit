import { describe, expect, it } from "vitest";
import { CLOSURE_BADGE, CLOSURE_LABEL, CUSTODY_EVENT_LABEL, formatHours, shortHash, summarizeCustody } from "./trust";

describe("summarizeCustody", () => {
  it("cambio de estado de caso muestra titulo y estados legibles", () => {
    const s = summarizeCustody("case.status_changed", { from: "open", to: "in_progress", case: { title: "Phishing" } });
    expect(s).toBe("Phishing: Abierto → En curso");
  });
  it("alerta creada une regla, severidad y host", () => {
    expect(summarizeCustody("alert.created", { rule: "R1", severity: "high", host: "srv1" })).toBe("R1 · high · srv1");
  });
  it("escaneo usa el traductor para la cantidad de hallazgos", () => {
    const tr = (k: string, ...a: (string | number)[]) => k.replace("{0}", String(a[0])).toUpperCase();
    expect(summarizeCustody("scan.completed", { scanner: "nmap", target: "10.0.0.1", findings: 3 }, tr)).toContain("3 HALLAZGOS");
  });
  it("evento desconocido cae al JSON recortado", () => {
    expect(summarizeCustody("otro.evento", { a: 1 })).toBe('{"a":1}');
  });
  it("todas las etiquetas existen y shortHash recorta", () => {
    expect(CUSTODY_EVENT_LABEL["evidence.exported"]).toBeTruthy();
    expect(shortHash("a".repeat(64))).toHaveLength(13);
    expect(shortHash("abc")).toBe("abc");
  });
});

describe("summarizeCustody: soberania", () => {
  it("prueba de salida y cambio de modo", () => {
    expect(summarizeCustody("sovereignty.probe", { reachable: 0, total: 3 })).toBe("0 de 3 destinos alcanzables");
    expect(summarizeCustody("sovereignty.mode_changed", { service: "siem-service", isolated_after: true })).toBe(
      "siem-service: modo aislado activado");
    expect(summarizeCustody("sovereignty.mode_changed", { service: "siem-service", isolated_after: false })).toBe(
      "siem-service: modo aislado desactivado");
  });
});

describe("cierre verificado", () => {
  it("formatea horas y dias", () => {
    expect(formatHours(null)).toBe("-");
    expect(formatHours(26.54)).toBe("26.5 h");
    expect(formatHours(47.9)).toBe("47.9 h");
    expect(formatHours(72)).toBe("3 d");
    expect(formatHours(60)).toBe("2.5 d");
  });
  it("cada estado tiene etiqueta y color", () => {
    for (const k of ["", "pending", "verified", "failed", "inconclusive", "unsupported"]) {
      expect(CLOSURE_LABEL[k]).toBeTruthy();
      expect(CLOSURE_BADGE[k]).toContain("badge");
    }
  });
  it("resume los eventos de cierre", () => {
    expect(summarizeCustody("vuln.closure_verified", { title: "Panel expuesto" })).toBe("Panel expuesto");
    expect(summarizeCustody("vuln.closure_failed", { title: "Panel", from: "remediated", to: "open" })).toBe("Panel: Remediada → Abierto");
  });
});
