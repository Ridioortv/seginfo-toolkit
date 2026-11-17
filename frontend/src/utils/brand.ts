// Marca propia (white label) del partner / cliente: tipos y helpers puros.
export interface Brand { name: string; color: string; logo: string; is_partner: boolean; acting_for_partner: boolean; organization_name: string }

export const LOGO_MAX_BYTES = 150 * 1024;
const COLOR = /^#[0-9a-fA-F]{6}$/;

export function validColor(value: string): boolean {
  return COLOR.test(value.trim());
}

/** Negro o blanco, el que mejor se lee sobre ese color de fondo (formula de luminancia relativa de WCAG). */
export function readableTextOn(color: string): "#ffffff" | "#0b1020" {
  if (!validColor(color)) return "#ffffff";
  const lin = (v: number) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
  const n = parseInt(color.slice(1), 16);
  const l = 0.2126 * lin(((n >> 16) & 255) / 255) + 0.7152 * lin(((n >> 8) & 255) / 255) + 0.0722 * lin((n & 255) / 255);
  // contraste con blanco = 1.05 / (l + 0.05); con el oscuro (~0.005) = (l + 0.05) / 0.055
  return 1.05 / (l + 0.05) >= (l + 0.05) / 0.055 ? "#ffffff" : "#0b1020";
}

/** Aplica (o quita, si no hay color) el color de marca a toda la interfaz. */
export function applyBrandColor(color: string | null | undefined, root: HTMLElement = document.documentElement): void {
  if (color && validColor(color)) {
    root.setAttribute("data-brand", "1");
    root.style.setProperty("--brand", color);
    root.style.setProperty("--brand-text", readableTextOn(color));
  } else {
    root.removeAttribute("data-brand");
    root.style.removeProperty("--brand");
    root.style.removeProperty("--brand-text");
  }
}

export type LogoCheck = { ok: true } | { ok: false; reason: string };

/** Revisa el archivo elegido antes de subirlo (el servidor lo vuelve a revisar). */
export function checkLogoFile(file: { type: string; size: number }): LogoCheck {
  if (file.type !== "image/png" && file.type !== "image/jpeg") return { ok: false, reason: "El logo tiene que ser una imagen PNG o JPEG." };
  if (file.size > LOGO_MAX_BYTES) return { ok: false, reason: "El logo pesa mas de 150 KB." };
  return { ok: true };
}

/** Minutos que le quedan al token de entrada a un cliente (0 si ya vencio). */
export function minutesLeft(exp: number | undefined, nowMs: number = Date.now()): number {
  if (!exp) return 0;
  return Math.max(0, Math.ceil((exp * 1000 - nowMs) / 60000));
}
