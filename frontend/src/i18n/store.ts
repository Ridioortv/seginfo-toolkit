import { create } from "zustand";
import { DEFAULT_LANG, LANGUAGES, LANG_STORAGE_KEY, detectLang, type Lang } from "./languages";
import { translateKey } from "./translate";

function readStored(): string | null {
  try {
    return window.localStorage.getItem(LANG_STORAGE_KEY);
  } catch {
    return null;
  }
}

function initialLang(): Lang {
  try {
    return detectLang(readStored(), navigator.languages?.length ? navigator.languages : navigator.language);
  } catch {
    return DEFAULT_LANG;
  }
}

type LangState = { lang: Lang; setLang: (lang: Lang) => void };

export const useLangStore = create<LangState>((set) => ({
  lang: initialLang(),
  setLang: (lang) => {
    try {
      window.localStorage.setItem(LANG_STORAGE_KEY, lang);
    } catch {
      // storage bloqueado (modo privado): el idioma vale solo para esta sesion
    }
    set({ lang });
  },
}));

export function currentLang(): Lang {
  return useLangStore.getState().lang;
}

/** Locale BCP-47 del idioma activo, para fechas y numeros. */
export function currentLocale(): string {
  const lang = currentLang();
  return LANGUAGES.find((l) => l.code === lang)?.locale ?? "es-AR";
}

/** Traduccion imperativa (window.confirm, etc.). `key` = texto en espanol con {0}, {1}... */
export function t(key: string, ...args: (string | number)[]): string {
  return translateKey(key, currentLang(), ...args);
}
