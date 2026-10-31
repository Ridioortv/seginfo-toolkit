import { describe, expect, it } from "vitest";
import { translate } from "../i18n/translate";
import {
  buildCiWorkflow, formatPct, isAiOrigin, orderedSeverities, policyScope, severityCounts, shortHash, shortSha,
  summarizePayload, weeklyBars, POLICY_TEMPLATES, EVENT_LABEL, GATE_REASON_LABEL,
  ORIGIN_LABEL, GATE_LABEL, REVIEW_LABEL, AI_POLICY_LABEL, MODE_LABEL, SEVERITY_LABEL, TRIGGER_LABEL, DETECTION_LABEL,
} from "./governance";

describe("governance helpers", () => {
  it("acorta hashes y shas", () => {
    expect(shortSha("a".repeat(40))).toBe("aaaaaaaa");
    expect(shortSha("abc")).toBe("abc");
    expect(shortHash("f".repeat(64))).toBe("ffffffffffff…");
  });

  it("cuenta y ordena hallazgos por severidad", () => {
    const counts = severityCounts([{ severity: "high" }, { severity: "low" }, { severity: "high" }, { severity: "raro" }]);
    expect(counts).toEqual({ high: 2, low: 2 });
    expect(orderedSeverities({ low: 1, critical: 3 })).toEqual([["critical", 3], ["low", 1]]);
  });

  it("formatea porcentajes y detecta origen IA", () => {
    expect(formatPct(50)).toBe("50%");
    expect(formatPct(66.7)).toBe("66.7%");
    expect(isAiOrigin("mixed") && isAiOrigin("ai") && !isAiOrigin("human")).toBe(true);
  });

  it("escala las barras semanales al maximo", () => {
    const bars = weeklyBars([
      { week: "2026-10-05", human_lines: 100, ai_lines: 100 },
      { week: "2026-10-12", human_lines: 50, ai_lines: 0 },
    ]);
    expect(bars[0]).toMatchObject({ humanPct: 50, aiPct: 50, total: 200 });
    expect(bars[1]).toMatchObject({ humanPct: 25, aiPct: 0 });
    expect(weeklyBars([])).toEqual([]);
  });

  it("resume el detalle de cada tipo de evento", () => {
    expect(summarizePayload("change.origin_declared", { before: { origin: "human" }, after: { origin: "mixed", ai_tool: "Cursor" } }))
      .toBe("Humano → Mixto (Cursor)");
    expect(summarizePayload("change.reviewed", { decision: "approve", comment: "ok" })).toBe("aprobo: ok");
    expect(summarizePayload("gate.evaluated", { previous_status: "blocked", status: "passed", policy: "P", mode: "enforce" }))
      .toBe("Bloqueado → Aprobado · P (Exigir)");
    expect(summarizePayload("scan.ingested", { repo: "api", new_changes: 3, ai_changes: 1 })).toBe("api: 3 nuevos, 1 con IA");
    expect(summarizePayload("desconocido", { a: 1 })).toBe('{"a":1}');
  });

  it("describe el alcance de una politica", () => {
    expect(policyScope({ path_prefixes: "", repo_target_id: null })).toBe("Todos los repositorios");
    expect(policyScope({ path_prefixes: "src/pagos/, infra/", repo_target_id: "r1", repo_name: "api" })).toBe("api · src/pagos/, infra/");
  });

  it("las plantillas de politica son validas para la API", () => {
    for (const t of POLICY_TEMPLATES) {
      expect(["observe", "enforce"]).toContain(t.value.mode);
      expect(["allowed", "restricted", "forbidden"]).toContain(t.value.ai_policy);
      expect(t.value.required_reviews).toBeGreaterThanOrEqual(0);
      expect(t.value.required_reviews).toBeLessThanOrEqual(3);
    }
    expect(POLICY_TEMPLATES[0].value.mode).toBe("observe"); // el arranque gradual es siempre el primero
  });

  it("el workflow de CI apunta al servicio y al repositorio, y corta si no esta permitido", () => {
    const yml = buildCiWorkflow("https://tero.acme.com:8015", "repo-123");
    expect(yml).toContain("TERO_URL: https://tero.acme.com:8015");
    expect(yml).toContain('--arg repo "repo-123"');
    expect(yml).toContain("secrets.TERO_TOKEN");
    expect(yml).toContain("/governance/gate/evaluate");
    expect(yml).toContain("exit 1");
  });

  it("hay etiqueta para todos los eventos y motivos que genera el backend", () => {
    for (const e of ["change.recorded", "change.origin_declared", "change.reviewed", "gate.evaluated", "policy.created",
      "policy.updated", "policy.deleted", "repo.connected", "repo.deleted", "scan.ingested", "change.finding_added"]) {
      expect(EVENT_LABEL[e], e).toBeTruthy();
    }
    for (const r of ["ai_forbidden", "findings_over_threshold", "missing_review", "review_rejected"]) {
      expect(GATE_REASON_LABEL[r], r).toBeTruthy();
    }
  });
});

describe("traducciones de las etiquetas de gobernanza", () => {
  const maps = [
    ORIGIN_LABEL, GATE_LABEL, REVIEW_LABEL, AI_POLICY_LABEL, MODE_LABEL,
    SEVERITY_LABEL, TRIGGER_LABEL, DETECTION_LABEL, EVENT_LABEL, GATE_REASON_LABEL,
  ];
  it("cada etiqueta tiene traduccion a zh y ru", () => {
    for (const m of maps) {
      for (const label of Object.values(m)) {
        for (const lang of ["zh", "ru"] as const) {
          expect(translate(label, lang), `${label} (${lang})`).not.toBe(label);
        }
      }
    }
  });
  it("las plantillas de politica tienen traduccion", () => {
    for (const tpl of POLICY_TEMPLATES) {
      expect(translate(tpl.label, "en")).not.toBe(tpl.label);
      expect(translate(tpl.hint, "ru")).not.toBe(tpl.hint);
    }
  });
});
