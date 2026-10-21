export type Lang = "es" | "en" | "zh" | "ru";

export const LANGUAGES: { code: Lang; label: string; short: string; locale: string }[] = [
  { code: "es", label: "Español", short: "ES", locale: "es-AR" },
  { code: "en", label: "English", short: "EN", locale: "en-US" },
  { code: "zh", label: "中文", short: "中文", locale: "zh-CN" },
  { code: "ru", label: "Русский", short: "RU", locale: "ru-RU" },
];

export const DEFAULT_LANG: Lang = "es";
export const LANG_STORAGE_KEY = "tero-lang";

export function isLang(value: unknown): value is Lang {
  return value === "es" || value === "en" || value === "zh" || value === "ru";
}

/** Idioma a usar la primera vez: el guardado, si no el del navegador, si no espanol. */
export function detectLang(stored: string | null, browser: readonly string[] | string | undefined): Lang {
  if (isLang(stored)) return stored;
  const list = typeof browser === "string" ? [browser] : [...(browser ?? [])];
  for (const raw of list) {
    const prefix = (raw ?? "").toLowerCase().split("-")[0];
    if (isLang(prefix)) return prefix;
  }
  return DEFAULT_LANG;
}
