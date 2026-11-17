import { describe, expect, it } from "vitest";
import { applyBrandColor, checkLogoFile, minutesLeft, readableTextOn, validColor } from "./brand";

describe("brand", () => {
  it("valida el color", () => {
    expect(validColor("#1a73e8")).toBe(true);
    expect(validColor("#1A73E8 ")).toBe(true);
    expect(validColor("rojo")).toBe(false);
    expect(validColor("#12345")).toBe(false);
    expect(validColor("url(javascript:1)")).toBe(false);
  });
  it("elige texto legible", () => {
    expect(readableTextOn("#0b6e4f")).toBe("#ffffff");
    expect(readableTextOn("#ffeb3b")).toBe("#0b1020");
    expect(readableTextOn("#000000")).toBe("#ffffff");
    expect(readableTextOn("basura")).toBe("#ffffff");
  });
  it("aplica y quita el color en el documento", () => {
    const attrs = new Map<string, string>(); const props = new Map<string, string>();
    const el = {
      setAttribute: (k: string, v: string) => attrs.set(k, v), removeAttribute: (k: string) => attrs.delete(k),
      getAttribute: (k: string) => attrs.get(k) ?? null, hasAttribute: (k: string) => attrs.has(k),
      style: { setProperty: (k: string, v: string) => props.set(k, v), removeProperty: (k: string) => props.delete(k), getPropertyValue: (k: string) => props.get(k) ?? "" },
    } as unknown as HTMLElement;
    applyBrandColor("#0b6e4f", el);
    expect(el.getAttribute("data-brand")).toBe("1");
    expect(el.style.getPropertyValue("--brand")).toBe("#0b6e4f");
    applyBrandColor("</style><script>", el);
    expect(el.hasAttribute("data-brand")).toBe(false);
    expect(el.style.getPropertyValue("--brand")).toBe("");
  });
  it("revisa el archivo del logo", () => {
    expect(checkLogoFile({ type: "image/png", size: 1000 }).ok).toBe(true);
    expect(checkLogoFile({ type: "image/svg+xml", size: 1000 }).ok).toBe(false);
    expect(checkLogoFile({ type: "image/jpeg", size: 151 * 1024 }).ok).toBe(false);
  });
  it("minutos restantes", () => {
    expect(minutesLeft(1000 + 600, 1000 * 1000)).toBe(10);
    expect(minutesLeft(10, 1000 * 1000)).toBe(0);
    expect(minutesLeft(undefined)).toBe(0);
  });
});
