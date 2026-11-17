/**
 * Interpreta el error de una llamada de login/registro (email+password,
 * Google o SSO) y devuelve el mensaje a mostrar y, si corresponde, el link
 * de pago (PayPal y/o Mercado Pago) para reactivar una organizacion con la
 * suscripcion vencida.
 *
 * El login devuelve 402 cuando la organizacion no tiene la suscripcion al
 * dia (ver _reject_if_org_inactive en auth-service/app/main.py). Ese 402
 * trae el "detail" como objeto ({message, payment_url}), no como string
 * plano -- payment_url viene armado por el servidor central de licencias
 * (PayPal) si esta configurado, o null si esta instalacion todavia
 * gestiona los pagos a mano (ahi solo se muestra el mensaje, sin boton).
 *
 * Extraida de Login.tsx como funcion pura para poder testearla sin
 * renderizar el componente.
 */
export interface LoginErrorResult {
  message: string;
  paymentUrl: string | null;
  // Un link por pasarela disponible (PayPal y/o Mercado Pago); vacio si no hay.
  paymentUrls: Partial<Record<PaymentProvider, string>>;
}

import { ALL_PROVIDER_IDS, isHttpUrl, pickPaymentUrls, type PaymentProvider } from "./payment";

/**
 * Lo que el 402 ofrece para pagar: las pasarelas disponibles y un pay_token.
 * El 402 YA NO trae links de pago (cada login bloqueado creaba una suscripcion
 * nueva en cada pasarela y quedaban todas pagables, con riesgo de doble cobro):
 * el link se pide recien cuando la persona elige "Pagar con ..." (ver
 * requestBlockedPaymentLink en services/api.ts). Sin pay_token no hay oferta.
 */
export interface PaymentOffer {
  providers: PaymentProvider[];
  payToken: string | null;
}

export const NO_PAYMENT_OFFER: PaymentOffer = { providers: [], payToken: null };

export function parsePaymentOffer(err: unknown): PaymentOffer {
  const axiosErr = err as { response?: { status?: number; data?: { detail?: unknown } } };
  const detail = axiosErr?.response?.data?.detail;
  if (axiosErr?.response?.status !== 402 || !detail || typeof detail !== "object") return NO_PAYMENT_OFFER;
  const d = detail as { payment_providers?: unknown; pay_token?: unknown };
  const payToken = typeof d.pay_token === "string" && d.pay_token ? d.pay_token : null;
  const raw = Array.isArray(d.payment_providers) ? d.payment_providers : [];
  const providers = ALL_PROVIDER_IDS.filter((id) => raw.includes(id));
  return payToken && providers.length ? { providers, payToken } : NO_PAYMENT_OFFER;
}

export function parseLoginError(err: unknown, fallback: string): LoginErrorResult {
  const axiosErr = err as { response?: { status?: number; data?: { detail?: unknown } } };
  const detail = axiosErr?.response?.data?.detail;

  if (axiosErr?.response?.status === 402) {
    if (detail && typeof detail === "object") {
      const d = detail as { message?: string; payment_url?: string | null; payment_urls?: unknown };
      const paymentUrls = pickPaymentUrls(d.payment_urls);
      // Servidores anteriores solo mandan payment_url (PayPal): se sigue entendiendo.
      if (isHttpUrl(d.payment_url) && Object.keys(paymentUrls).length === 0) {
        paymentUrls.paypal = d.payment_url;
      }
      return {
        message: d.message ?? "La suscripcion de esta organizacion no esta al dia.",
        paymentUrl: isHttpUrl(d.payment_url) ? d.payment_url : (Object.values(paymentUrls)[0] ?? null),
        paymentUrls,
      };
    }
    if (typeof detail === "string") {
      return { message: detail, paymentUrl: null, paymentUrls: {} };
    }
  }

  // 429: demasiados intentos. Sin esto se mostraba "Credenciales invalidas",
  // y la persona seguia probando claves que en realidad estaban bien.
  if (axiosErr?.response?.status === 429) {
    return {
      message:
        typeof detail === "string" && detail
          ? detail
          : "Demasiados intentos. Espera unos minutos antes de volver a intentar.",
      paymentUrl: null,
      paymentUrls: {},
    };
  }

  return { message: fallback, paymentUrl: null, paymentUrls: {} };
}
