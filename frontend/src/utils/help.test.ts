import { describe, expect, it } from "vitest";
import { filterHelpTopics, progressPercent } from "./help";

describe("progressPercent", () => {
  it("returns 0 when there are no topics", () => {
    expect(progressPercent(0, 0)).toBe(0);
  });

  it("returns 0 when nothing was read", () => {
    expect(progressPercent(11, 0)).toBe(0);
  });

  it("returns 100 when everything was read", () => {
    expect(progressPercent(11, 11)).toBe(100);
  });

  it("rounds to the nearest integer", () => {
    expect(progressPercent(11, 3)).toBe(27);
  });

  it("clamps a negative completed count to 0", () => {
    expect(progressPercent(5, -2)).toBe(0);
  });

  it("clamps a completed count above the total to 100", () => {
    expect(progressPercent(5, 9)).toBe(100);
  });
});

describe("filterHelpTopics", () => {
  const topics = [
    { id: "assets", label: "Activos", tagline: "Que equipos vigilas", overview: "Registra tus equipos.", steps: [{ title: "Agregar", body: "Completa el formulario." }] },
    { id: "siem", label: "SIEM", tagline: "Todo en un lugar", overview: "Reglas de deteccion.", steps: [{ title: "Cargar reglas", body: "Boton de reglas recomendadas." }] },
  ];

  it("returns every topic when the query is empty or blank", () => {
    expect(filterHelpTopics(topics, "")).toEqual(topics);
    expect(filterHelpTopics(topics, "   ")).toEqual(topics);
  });

  it("matches by label, case-insensitively", () => {
    expect(filterHelpTopics(topics, "siem")).toEqual([topics[1]]);
  });

  it("matches text inside a step's title or body", () => {
    expect(filterHelpTopics(topics, "recomendadas")).toEqual([topics[1]]);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterHelpTopics(topics, "algo que no existe")).toEqual([]);
  });
});
