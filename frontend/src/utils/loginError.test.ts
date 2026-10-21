import { describe, expect, it } from "vitest";
import { parseLoginError, parsePaymentOffer } from "./loginError";

function axiosError(status: number, detail: unknown) {
  return { response: { status, data: { detail } } };
}

describe("parseLoginError", () => {
  it("extracts message and payment_url from a 402 with object detail", () => {
    const err = axiosError(402, { message: "Suscripcion vencida", payment_url: "https://pay.example.com/pay/1" });
    expect(parseLoginError(err, "fallback")).toEqual({
      message: "Suscripcion vencida",
      paymentUrl: "https://pay.example.com/pay/1",
      paymentUrls: { paypal: "https://pay.example.com/pay/1" },
    });
  });

  it("defaults payment_url to null when the 402 object detail omits it", () => {
    const err = axiosError(402, { message: "Sin pasarela de pago configurada" });
    expect(parseLoginError(err, "fallback")).toEqual({
      message: "Sin pasarela de pago configurada",
      paymentUrl: null,
      paymentUrls: {},
    });
  });

  it("defaults payment_url to null when the server sends payment_url: null explicitly", () => {
    const err = axiosError(402, { message: "Suscripcion vencida", payment_url: null });
    expect(parseLoginError(err, "fallback")).toEqual({
      message: "Suscripcion vencida",
      paymentUrl: null,
      paymentUrls: {},
    });
  });

  it("uses a generic message when the 402 detail is an object without 'message'", () => {
    const err = axiosError(402, {});
    expect(parseLoginError(err, "fallback").message).toBe("La suscripcion de esta organizacion no esta al dia.");
  });

  it("falls back to the caller's fallback when the 402 has no detail at all", () => {
    const err = axiosError(402, undefined);
    expect(parseLoginError(err, "fallback")).toEqual({ message: "fallback", paymentUrl: null, paymentUrls: {} });
  });

  it("handles a 402 with a plain string detail (no payment link)", () => {
    const err = axiosError(402, "Organizacion suspendida");
    expect(parseLoginError(err, "fallback")).toEqual({ message: "Organizacion suspendida", paymentUrl: null, paymentUrls: {} });
  });

  it("falls back for a non-402 error (e.g. 401 invalid credentials)", () => {
    const err = axiosError(401, { detail: "Credenciales invalidas" });
    expect(parseLoginError(err, "Credenciales invalidas o MFA requerido.")).toEqual({
      message: "Credenciales invalidas o MFA requerido.",
      paymentUrl: null,
      paymentUrls: {},
    });
  });

  it("falls back for a network error with no response at all", () => {
    const err = { message: "Network Error" };
    expect(parseLoginError(err, "No se pudo iniciar sesion.")).toEqual({
      message: "No se pudo iniciar sesion.",
      paymentUrl: null,
      paymentUrls: {},
    });
  });

  it("reads one link per gateway when the server sends payment_urls", () => {
    const err = axiosError(402, {
      message: "Vencida",
      payment_url: "https://paypal.test/ok",
      payment_urls: { paypal: "https://paypal.test/ok", mercadopago: "https://mp.test/go" },
    });
    expect(parseLoginError(err, "fallback")).toEqual({
      message: "Vencida",
      paymentUrl: "https://paypal.test/ok",
      paymentUrls: { paypal: "https://paypal.test/ok", mercadopago: "https://mp.test/go" },
    });
  });

  it("works with only Mercado Pago available", () => {
    const err = axiosError(402, {
      message: "Vencida",
      payment_url: "https://mp.test/go",
      payment_urls: { mercadopago: "https://mp.test/go" },
    });
    const r = parseLoginError(err, "fallback");
    expect(r.paymentUrls).toEqual({ mercadopago: "https://mp.test/go" });
    expect(r.paymentUrl).toBe("https://mp.test/go");
  });

  it("drops links that are not http(s)", () => {
    const err = axiosError(402, {
      message: "Vencida",
      payment_url: "javascript:alert(1)",
      payment_urls: { paypal: "javascript:alert(1)", mercadopago: "https://mp.test/go" },
    });
    const r = parseLoginError(err, "fallback");
    expect(r.paymentUrls).toEqual({ mercadopago: "https://mp.test/go" });
    expect(r.paymentUrl).toBe("https://mp.test/go");
  });
  it("explains a 429 (too many attempts) instead of saying the credentials are wrong", () => {
    const r = parseLoginError({ response: { status: 429, data: { detail: "Demasiados intentos. Espera unos minutos antes de volver a intentar." } } }, "Credenciales invalidas");
    expect(r.message).toContain("Demasiados intentos");
    expect(r.paymentUrl).toBeNull();
  });
});

describe("parsePaymentOffer", () => {
  it("reads the gateways and the pay_token from a 402", () => {
    const err = axiosError(402, { message: "Vencida", payment_providers: ["mercadopago", "paypal"], pay_token: "tok.en.123" });
    expect(parsePaymentOffer(err)).toEqual({ providers: ["paypal", "mercadopago"], payToken: "tok.en.123" });
  });

  it("offers nothing without a pay_token (nothing could be generated)", () => {
    const err = axiosError(402, { message: "Vencida", payment_providers: ["paypal"], pay_token: null });
    expect(parsePaymentOffer(err)).toEqual({ providers: [], payToken: null });
  });

  it("offers nothing when the server lists no gateway", () => {
    const err = axiosError(402, { message: "Vencida", payment_providers: [], pay_token: "tok.en.123" });
    expect(parsePaymentOffer(err)).toEqual({ providers: [], payToken: null });
  });

  it("ignores unknown gateways", () => {
    const err = axiosError(402, { payment_providers: ["bitcoin", "paypal"], pay_token: "tok.en.123" });
    expect(parsePaymentOffer(err).providers).toEqual(["paypal"]);
  });

  it("offers nothing for errors that are not a 402 with an object detail", () => {
    expect(parsePaymentOffer(axiosError(401, "x"))).toEqual({ providers: [], payToken: null });
    expect(parsePaymentOffer(axiosError(402, "Organizacion suspendida"))).toEqual({ providers: [], payToken: null });
    expect(parsePaymentOffer({ message: "Network Error" })).toEqual({ providers: [], payToken: null });
  });
});
