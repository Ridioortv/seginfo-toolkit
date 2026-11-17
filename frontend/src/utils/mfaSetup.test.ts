import { describe, expect, it } from "vitest";
import { groupSecret, normalizeTotp, totpProblem } from "./mfaSetup";

describe("totpProblem", () => {
  it("acepta 6 digitos, con o sin espacios", () => {
    expect(totpProblem("123456")).toBeNull();
    expect(totpProblem(" 123 456 ")).toBeNull();
  });
  it("rechaza lo que no son 6 digitos", () => {
    for (const bad of ["", "12345", "1234567", "abcdef", "12 34 5a"]) {
      expect(totpProblem(bad)).toMatch(/6 digitos/);
    }
  });
});

describe("normalizeTotp / groupSecret", () => {
  it("saca los espacios del codigo", () => {
    expect(normalizeTotp("123 456")).toBe("123456");
  });
  it("agrupa la clave de a 4", () => {
    expect(groupSecret("ABCDEFGHIJ")).toBe("ABCD EFGH IJ");
    expect(groupSecret("ABCD EFGH")).toBe("ABCD EFGH");
  });
});
