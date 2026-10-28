import { describe, expect, it } from "vitest";
import { canEnter, expiryNote, figure } from "./partner";

describe("partner", () => {
  it("un cliente suspendido no se puede abrir", () => {
    expect(canEnter({ is_active: true })).toBe(true);
    expect(canEnter({ is_active: false })).toBe(false);
  });
  it("vencimiento", () => {
    const now = new Date("2026-06-01T00:00:00Z").getTime();
    expect(expiryNote(null, now).key).toBe("none");
    expect(expiryNote("2026-05-30T00:00:00Z", now).key).toBe("expired");
    expect(expiryNote("2026-06-04T00:00:00Z", now)).toEqual({ key: "soon", days: 3 });
    expect(expiryNote("2026-08-01T00:00:00Z", now).key).toBe("ok");
  });
  it("las cifras que faltan no son cero", () => {
    expect(figure(null)).toBe("-");
    expect(figure(undefined)).toBe("-");
    expect(figure(0)).toBe("0");
    expect(figure(7)).toBe("7");
  });
});
