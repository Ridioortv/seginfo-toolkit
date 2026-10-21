import { describe, expect, it } from "vitest";
import { isHttpUrl, pickPaymentUrls, pickProviders, providerLabel } from "./payment";

describe("payment utils", () => {
  it("acepta solo links http(s)", () => {
    expect(isHttpUrl("https://www.paypal.com/x")).toBe(true);
    expect(isHttpUrl("http://localhost:1/x")).toBe(true);
    expect(isHttpUrl("javascript:alert(1)")).toBe(false);
    expect(isHttpUrl("data:text/html,hola")).toBe(false);
    expect(isHttpUrl("no es una url")).toBe(false);
    expect(isHttpUrl(null)).toBe(false);
    expect(isHttpUrl(42)).toBe(false);
  });

  it("pickPaymentUrls se queda con las pasarelas conocidas y validas", () => {
    expect(
      pickPaymentUrls({
        paypal: "https://paypal.test/ok",
        mercadopago: "javascript:alert(1)",
        bitcoin: "https://btc.test",
      }),
    ).toEqual({ paypal: "https://paypal.test/ok" });
    expect(pickPaymentUrls(null)).toEqual({});
    expect(pickPaymentUrls("x")).toEqual({});
  });

  it("providerLabel devuelve el nombre visible", () => {
    expect(providerLabel("paypal")).toBe("PayPal");
    expect(providerLabel("mercadopago")).toBe("Mercado Pago");
  });

  it("pickProviders respeta lo que ofrece el servidor y nunca deja sin pasarelas", () => {
    expect(pickProviders(["mercadopago"])).toEqual(["mercadopago"]);
    expect(pickProviders(["mercadopago", "paypal"])).toEqual(["paypal", "mercadopago"]);
    expect(pickProviders(["otra", "mercadopago"])).toEqual(["mercadopago"]);
    expect(pickProviders([])).toEqual(["paypal", "mercadopago"]);
    expect(pickProviders(["otra"])).toEqual(["paypal", "mercadopago"]);
    expect(pickProviders(undefined)).toEqual(["paypal", "mercadopago"]);
    expect(pickProviders("mercadopago")).toEqual(["paypal", "mercadopago"]);
  });
});
