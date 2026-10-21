// Pasarelas de pago de la suscripcion. PayPal cobra USD 250 cada 30 dias;
// Mercado Pago cobra el equivalente en pesos (USD 250 al cambio del dia) con
// debito automatico cada 30 dias. Los links los arma el servidor central de
// licencias (ver backend/shared/license_check.py).
export type PaymentProvider = "paypal" | "mercadopago";

export interface PaymentProviderInfo {
  id: PaymentProvider;
  label: string;
  hint: string;
}

export const PAYMENT_PROVIDERS: PaymentProviderInfo[] = [
  { id: "paypal", label: "PayPal", hint: "USD 250 cada 30 dias. Tarjeta o saldo PayPal." },
  {
    id: "mercadopago",
    label: "Mercado Pago",
    hint: "En pesos: USD 250 al cambio del dia. Debito automatico cada 30 dias.",
  },
];

export const ALL_PROVIDER_IDS: PaymentProvider[] = PAYMENT_PROVIDERS.map((p) => p.id);

// Pasarelas conocidas que el servidor dice ofrecer (en el orden de PAYMENT_PROVIDERS).
// Si no manda ninguna valida se asumen todas, para no dejar sin forma de pagar.
export function pickProviders(raw: unknown): PaymentProvider[] {
  if (!Array.isArray(raw)) return [...ALL_PROVIDER_IDS];
  const chosen = ALL_PROVIDER_IDS.filter((id) => raw.includes(id));
  return chosen.length ? chosen : [...ALL_PROVIDER_IDS];
}

export function providerLabel(id: PaymentProvider): string {
  return PAYMENT_PROVIDERS.find((p) => p.id === id)?.label ?? id;
}

// Solo se abren links http(s): el link viene de un servidor remoto y se usa
// como href / window.open, asi que un "javascript:" o "data:" no puede pasar.
export function isHttpUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

// Deja solo las pasarelas conocidas con un link valido.
export function pickPaymentUrls(raw: unknown): Partial<Record<PaymentProvider, string>> {
  const out: Partial<Record<PaymentProvider, string>> = {};
  if (!raw || typeof raw !== "object") return out;
  for (const { id } of PAYMENT_PROVIDERS) {
    const url = (raw as Record<string, unknown>)[id];
    if (isHttpUrl(url)) out[id] = url;
  }
  return out;
}
