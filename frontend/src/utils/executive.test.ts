import { describe, expect, it } from "vitest";
import { changeText, fmtMsg, hoursText, sparkPoints, tone } from "./executive";

describe("executive helpers", () => {
  it("shows the change against the previous period", () => {
    expect(changeText({ current: 10, previous: 8, change: 2, change_pct: 25 })).toBe("+2 (+25%)");
    expect(changeText({ current: 6, previous: 8, change: -2, change_pct: -25 })).toBe("-2 (-25%)");
    expect(changeText({ current: 3, previous: 0, change: 3, change_pct: null })).toBe("+3");
    expect(changeText({ current: 3, previous: null, change: null, change_pct: null })).toMatch(/comparacion/);
    expect(changeText(undefined)).toMatch(/comparacion/);
  });

  it("decides if a change is good depending on what is measured", () => {
    expect(tone(-3, "down")).toBe("good");
    expect(tone(3, "down")).toBe("bad");
    expect(tone(3, "up")).toBe("good");
    expect(tone(0, "up")).toBe("neutral");
    expect(tone(null, "down")).toBe("neutral");
  });

  it("fills API message placeholders", () => {
    expect(fmtMsg({ text: "{0} de {1} cosas", args: ["2", "5"] })).toBe("2 de 5 cosas");
  });

  it("formats hours and days", () => {
    expect(hoursText(null)).toBe("-");
    expect(hoursText(12.34)).toContain("12.3");
    expect(hoursText(96)).toContain("4");
  });

  it("builds a sparkline only with two or more points and skips gaps", () => {
    expect(sparkPoints([null, 3], 100, 40)).toBeNull();
    const pts = sparkPoints([1, null, 3, 2], 100, 40)!;
    expect(pts.split(" ")).toHaveLength(3);
    const ys = pts.split(" ").map((p) => Number(p.split(",")[1]));
    expect(ys[1]).toBeLessThan(ys[0]); // el 3 queda mas arriba (y menor) que el 1
  });
});
