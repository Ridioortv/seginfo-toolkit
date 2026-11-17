import { describe, expect, it } from "vitest";
import { campaignTarget, sumCounts, vercelEnvBlock } from "./antiestafa";

describe("antiestafa utils", () => {
  it("interpreta la clave de una campana", () => {
    expect(campaignTarget("dominio:mercadopag0.example")).toEqual({ kind: "dominio", value: "mercadopag0.example" });
    expect(campaignTarget("huella:2d71").kind).toBe("mensaje");
  });

  it("arma las variables para Vercel con la ruta de ingesta", () => {
    const block = vercelEnvBlock("https://tero.acme.com.ar/api/siem/", "tok", "org-1", "/integrations/antiestafa/events");
    expect(block).toContain("TERO_SIEM_URL=https://tero.acme.com.ar/api/siem/integrations/antiestafa/events");
    expect(block).toContain("TERO_API_KEY=tok");
    expect(block).toContain("TERO_ORGANIZACION=org-1");
    expect(block).toContain("TERO_INCLUIR_TEXTO=false");
  });

  it("sin direccion publica usa un ejemplo y sin token deja un marcador", () => {
    const block = vercelEnvBlock("", "", "o", "/x");
    expect(block).toContain("https://tero.tu-empresa.com.ar/api/siem/x");
    expect(block).toContain("<token de ingesta>");
  });

  it("suma conteos", () => {
    expect(sumCounts({ a: 2, b: 3 })).toBe(5);
    expect(sumCounts({})).toBe(0);
  });
});
