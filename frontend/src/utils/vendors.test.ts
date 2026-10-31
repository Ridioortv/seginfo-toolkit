import { describe, expect, it } from "vitest";
import { assessmentLink, dateToIso, groupByDomain, unanswered } from "./vendors";

describe("vendors utils", () => {
  it("arma el link sin barras dobles", () => {
    expect(assessmentLink("https://tero.acme.com/", "/proveedor/abc")).toBe("https://tero.acme.com/proveedor/abc");
  });
  it("agrupa por dominio en orden", () => {
    const g = groupByDomain([{ domain: "A", id: 1 }, { domain: "A", id: 2 }, { domain: "B", id: 3 }]);
    expect(g.map(([d, items]) => [d, items.length])).toEqual([["A", 2], ["B", 1]]);
  });
  it("cuenta las preguntas sin responder", () => {
    const qs = [{ id: "a", domain: "x", text: "" }, { id: "b", domain: "x", text: "" }];
    expect(unanswered(qs, { a: "yes" })).toBe(1);
    expect(unanswered(qs, {})).toBe(2);
  });
  it("convierte fecha a ISO a mediodia UTC o null si esta vacia", () => {
    expect(dateToIso("2027-01-31")).toBe("2027-01-31T12:00:00Z");
    expect(dateToIso("")).toBeNull();
  });
});
