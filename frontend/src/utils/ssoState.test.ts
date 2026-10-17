import { describe, expect, it } from "vitest";
import { consumeClientState, generateClientState, storeClientState, type StateStore } from "./ssoState";

function memoryStore(): StateStore & { data: Record<string, string> } {
  const data: Record<string, string> = {};
  return {
    data,
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => {
      data[k] = v;
    },
    removeItem: (k) => {
      delete data[k];
    },
  };
}

describe("ssoState", () => {
  it("acepta el valor que la SPA guardo y es de un solo uso", () => {
    const store = memoryStore();
    const cs = generateClientState();
    expect(cs).toMatch(/^[0-9a-f]{48}$/);
    expect(storeClientState(cs, store)).toBe(true);
    expect(consumeClientState(cs, store)).toBe(true);
    expect(consumeClientState(cs, store)).toBe(false);
  });

  it("rechaza un link armado por un atacante (sin cs o con otro cs)", () => {
    const store = memoryStore();
    storeClientState(generateClientState(), store);
    expect(consumeClientState(null, store)).toBe(false);
    storeClientState(generateClientState(), store);
    expect(consumeClientState("a".repeat(48), store)).toBe(false);
  });

  it("rechaza si la victima nunca inicio un login SSO en este navegador", () => {
    expect(consumeClientState("a".repeat(48), memoryStore())).toBe(false);
  });

  it("sin sessionStorage disponible no instala nada", () => {
    expect(consumeClientState("x", null)).toBe(false);
    expect(storeClientState("x", null)).toBe(false);
  });
});
