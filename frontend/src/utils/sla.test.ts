import { describe, expect, it } from "vitest";
import { isSlaBreached } from "./sla";

const NOW = "2026-09-23T12:00:00.000Z";

describe("isSlaBreached", () => {
  it("returns false when there is no SLA deadline", () => {
    expect(isSlaBreached(null, "open", NOW)).toBe(false);
  });

  it("returns false when the deadline is in the future", () => {
    expect(isSlaBreached("2026-09-24T00:00:00.000Z", "open", NOW)).toBe(false);
  });

  it("returns true when the deadline passed and the case is still open", () => {
    expect(isSlaBreached("2026-09-23T00:00:00.000Z", "open", NOW)).toBe(true);
  });

  it("returns true for an in_progress case past its deadline", () => {
    expect(isSlaBreached("2026-09-23T00:00:00.000Z", "in_progress", NOW)).toBe(true);
  });

  it("returns false once the case is resolved, even if the deadline passed", () => {
    expect(isSlaBreached("2026-09-23T00:00:00.000Z", "resolved", NOW)).toBe(false);
  });

  it("returns false once the case is closed, even if the deadline passed", () => {
    expect(isSlaBreached("2026-09-23T00:00:00.000Z", "closed", NOW)).toBe(false);
  });
});
