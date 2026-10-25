import { describe, expect, it } from "vitest";
import {
  ANSWER_BADGE, ANSWER_LABEL, CLOSURE_BADGE, CLOSURE_LABEL, CONTROL_STATUS_BADGE, CONTROL_STATUS_LABEL, CUSTODY_EVENT_LABEL,
  canDeclare, formatHours, needsAction, shortHash, sparkPoints, summarizeCustody,
} from "./trust";

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

describe("cumplimiento", () => {
  const STATUSES = ["cumple", "parcial", "no_cumple", "declarado_si", "declarado_parcial", "declarado_no", "pendiente", "vencido", "sin_datos"] as const;
  it("todos los estados tienen etiqueta y color", () => {
    for (const st of STATUSES) {
      expect(CONTROL_STATUS_LABEL[st]).toBeTruthy();
      expect(CONTROL_STATUS_BADGE[st]).toMatch(/^badge /);
    }
    for (const a of ["yes", "partial", "no", "pending"]) {
      expect(ANSWER_LABEL[a]).toBeTruthy();
      expect(ANSWER_BADGE[a]).toMatch(/^badge /);
    }
  });
  it("needsAction solo deja afuera lo que cumple o esta declarado que si", () => {
    expect(STATUSES.filter((st) => !needsAction({ status: st }))).toEqual(["cumple", "declarado_si"]);
  });
  it("se declara a mano lo manual y lo automatico sin datos, nunca lo que TERO ya verifico", () => {
    expect(canDeclare({ mode: "manual", status: "pendiente", basis: "ninguno" })).toBe(true);
    expect(canDeclare({ mode: "auto", status: "sin_datos", basis: "ninguno" })).toBe(true);
    expect(canDeclare({ mode: "auto", status: "declarado_si", basis: "declarado" })).toBe(true);
    expect(canDeclare({ mode: "auto", status: "no_cumple", basis: "verificado" })).toBe(false);
    expect(canDeclare({ mode: "auto", status: "cumple", basis: "verificado" })).toBe(false);
  });
  it("sparkPoints escala 0-100 al alto y saltea los vacios", () => {
    const h = [
      { id: "1", created_at: "", score_verified: 0, score_total: 50 },
      { id: "2", created_at: "", score_verified: null, score_total: 100 },
      { id: "3", created_at: "", score_verified: 100, score_total: 100 },
    ];
    expect(sparkPoints(h, "score_verified", 100, 40)).toBe("0,40 100,0");
    expect(sparkPoints(h, "score_total", 100, 40)).toBe("0,20 50,0 100,0");
    expect(sparkPoints([], "score_total", 100, 40)).toBe("");
    expect(sparkPoints([h[0]], "score_total", 100, 40)).toBe("0,20");
  });
});
