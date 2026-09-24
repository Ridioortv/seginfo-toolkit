import { describe, expect, it } from "vitest";
import { parseLoginError } from "./loginError";

function axiosError(status: number, detail: unknown) {
  return { response: { status, data: { detail } } };
}

describe("parseLoginError", () => {
  it("extracts message and payment_url from a 402 with object detail", () => {
    const err = axiosError(402, { message: "Suscripcion vencida", payment_url: "https://mp.example.com/pay/1" });
    expect(parseLoginError(err, "fallback")).toEqual({
      message: "Suscripcion vencida",
      paymentUrl: "https://mp.example.com/pay/1",
    });
  });

  it("defaults payment_url to null when the 402 object detail omits it", () => {
    const err = axiosError(402, { message: "Sin pasarela de pago configurada" });
    expect(parseLoginError(err, "fallback")).toEqual({
      message: "Sin pasarela de pago configurada",
      paymentUrl: null,
    });
  });

  it("defaults payment_url to null when the server sends payment_url: null explicitly", () => {
    const err = axiosError(402, { message: "Suscripcion vencida", payment_url: null });
    expect(parseLoginError(err, "fallback")).toEqual({
      message: "Suscripcion vencida",
      paymentUrl: null,
    });
  });

  it("uses a generic message when the 402 detail is an object without 'message'", () => {
    const err = axiosError(402, {});
    expect(parseLoginError(err, "fallback").message).toBe("La suscripcion de esta organizacion no esta al dia.");
  });

  it("falls back to the caller's fallback when the 402 has no detail at all", () => {
    const err = axiosError(402, undefined);
    expect(parseLoginError(err, "fallback")).toEqual({ message: "fallback", paymentUrl: null });
  });

  it("handles a 402 with a plain string detail (no payment link)", () => {
    const err = axiosError(402, "Organizacion suspendida");
    expect(parseLoginError(err, "fallback")).toEqual({ message: "Organizacion suspendida", paymentUrl: null });
  });

  it("falls back for a non-402 error (e.g. 401 invalid credentials)", () => {
    const err = axiosError(401, { detail: "Credenciales invalidas" });
    expect(parseLoginError(err, "Credenciales invalidas o MFA requerido.")).toEqual({
      message: "Credenciales invalidas o MFA requerido.",
      paymentUrl: null,
    });
  });

  it("falls back for a network error with no response at all", () => {
    const err = { message: "Network Error" };
    expect(parseLoginError(err, "No se pudo iniciar sesion.")).toEqual({
      message: "No se pudo iniciar sesion.",
      paymentUrl: null,
    });
  });
});
