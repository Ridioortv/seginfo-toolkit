import { describe, expect, it } from "vitest";
import { formatDate } from "./format";

describe("formatDate", () => {
  it("returns '--' for null", () => {
    expect(formatDate(null)).toBe("--");
  });

  it("returns '--' for undefined", () => {
    expect(formatDate(undefined)).toBe("--");
  });

  it("returns '--' for an empty string", () => {
    expect(formatDate("")).toBe("--");
  });

  it("formats an ISO date string in es-AR (dd/mm/aaaa)", () => {
    expect(formatDate("2026-03-15T00:00:00Z")).toBe(new Date("2026-03-15T00:00:00Z").toLocaleDateString("es-AR"));
  });
});
