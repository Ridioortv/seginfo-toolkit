import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { applyTheme, currentTheme, getStoredTheme, isTheme, THEME_STORAGE_KEY, toggleTheme } from "./theme";

// El entorno de vitest es "node" (sin jsdom): se simulan solo las dos
// piezas que usa theme.ts -- localStorage y el atributo del <html>.
function installFakes(opts: { storageThrows?: boolean; prefersLight?: boolean } = {}) {
  const store = new Map<string, string>();
  const attrs = new Map<string, string>();
  vi.stubGlobal("window", {
    localStorage: {
      getItem: (k: string) => {
        if (opts.storageThrows) throw new Error("blocked");
        return store.has(k) ? store.get(k)! : null;
      },
      setItem: (k: string, v: string) => {
        if (opts.storageThrows) throw new Error("blocked");
        store.set(k, v);
      },
    },
    matchMedia: () => ({ matches: opts.prefersLight ?? false }),
  });
  vi.stubGlobal("document", {
    documentElement: {
      getAttribute: (k: string) => attrs.get(k) ?? null,
      setAttribute: (k: string, v: string) => void attrs.set(k, v),
    },
  });
  return { store, attrs };
}

describe("theme", () => {
  beforeEach(() => {
    installFakes();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("solo acepta dark y light", () => {
    expect(isTheme("dark")).toBe(true);
    expect(isTheme("light")).toBe(true);
    expect(isTheme("blue")).toBe(false);
    expect(isTheme(null)).toBe(false);
  });

  it("ignora un valor guardado invalido", () => {
    const { store } = installFakes();
    store.set(THEME_STORAGE_KEY, "<script>");
    expect(getStoredTheme()).toBeNull();
  });

  it("applyTheme marca el documento y guarda la preferencia", () => {
    const { attrs } = installFakes();
    applyTheme("light");
    expect(attrs.get("data-theme")).toBe("light");
    expect(getStoredTheme()).toBe("light");
  });

  it("applyTheme sin persistir no escribe en storage", () => {
    installFakes();
    applyTheme("light", false);
    expect(getStoredTheme()).toBeNull();
  });

  it("toggleTheme alterna entre oscuro y claro", () => {
    installFakes();
    applyTheme("dark");
    expect(toggleTheme()).toBe("light");
    expect(currentTheme()).toBe("light");
    expect(toggleTheme()).toBe("dark");
  });

  it("sin preferencia guardada sigue la del sistema", () => {
    installFakes({ prefersLight: true });
    expect(currentTheme()).toBe("light");
  });

  it("no rompe si el storage lanza error", () => {
    const { attrs } = installFakes({ storageThrows: true });
    expect(() => applyTheme("light")).not.toThrow();
    expect(attrs.get("data-theme")).toBe("light");
    expect(getStoredTheme()).toBeNull();
  });
});
