import { describe, expect, it } from "vitest";
import { canApprove, canDecide, maxDays, needsException } from "./exceptions";

describe("exceptions utils", () => {
  it("topes de duracion por severidad", () => {
    expect(maxDays("critical")).toBe(90);
    expect(maxDays("high")).toBe(180);
    expect(maxDays("medium")).toBe(365);
  });
  it("alta y critica necesitan excepcion, salvo que ya este aceptada", () => {
    expect(needsException("critical", "open")).toBe(true);
    expect(needsException("high", "confirmed")).toBe(true);
    expect(needsException("medium", "open")).toBe(false);
    expect(needsException("high", "accepted_risk")).toBe(false);
  });
  it("una critica solo la decide un admin", () => {
    expect(canDecide("admin", "critical")).toBe(true);
    expect(canDecide("soc_manager", "critical")).toBe(false);
    expect(canDecide("soc_manager", "high")).toBe(true);
    expect(canDecide("analyst", "low")).toBe(false);
  });
  it("nadie aprueba su propio pedido salvo que se permita", () => {
    const row = { requested_by: "Ana@acme.com", severity: "high", status: "pending" as const };
    expect(canApprove(row, "ana@acme.com", "admin", false)).toBe(false);
    expect(canApprove(row, "ana@acme.com", "admin", true)).toBe(true);
    expect(canApprove(row, "otro@acme.com", "soc_manager", false)).toBe(true);
    expect(canApprove({ ...row, status: "approved" as never }, "otro@acme.com", "admin", false)).toBe(false);
  });
});
