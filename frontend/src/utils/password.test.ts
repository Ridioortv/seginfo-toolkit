import { describe, expect, it } from "vitest";
import { passwordProblem, tokenFromSearch } from "./password";

describe("passwordProblem", () => {
  it("rechaza menos de 12 caracteres", () => {
    expect(passwordProblem("corta", "corta")).toMatch(/12 caracteres/);
  });
  it("rechaza si no coinciden", () => {
    expect(passwordProblem("una-clave-larga-1", "una-clave-larga-2")).toMatch(/no coinciden/);
  });
  it("rechaza mas de 128", () => {
    const larga = "a".repeat(129);
    expect(passwordProblem(larga, larga)).toMatch(/128/);
  });
  it("acepta una contrasena valida repetida igual", () => {
    expect(passwordProblem("una-clave-larga-1", "una-clave-larga-1")).toBeNull();
  });
});

describe("tokenFromSearch", () => {
  it("lee el token del link", () => {
    expect(tokenFromSearch("?token=abc.def.ghi")).toBe("abc.def.ghi");
  });
  it("devuelve vacio si falta", () => {
    expect(tokenFromSearch("")).toBe("");
    expect(tokenFromSearch("?otro=1")).toBe("");
  });
});
