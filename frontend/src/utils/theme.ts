// Tema claro/oscuro. La preferencia vive solo en este navegador
// (localStorage) y, si no hay una guardada, se sigue la del sistema
// operativo. Todo el acceso a storage va en try/catch: en modo privado o
// con el storage bloqueado la app tiene que seguir funcionando.

export type Theme = "dark" | "light";

export const THEME_STORAGE_KEY = "tero-theme";

export function isTheme(value: unknown): value is Theme {
  return value === "dark" || value === "light";
}

export function getStoredTheme(): Theme | null {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(value) ? value : null;
  } catch {
    return null;
  }
}

export function systemTheme(): Theme {
  try {
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function currentTheme(): Theme {
  const attr = document.documentElement.getAttribute("data-theme");
  return isTheme(attr) ? attr : getStoredTheme() ?? systemTheme();
}

export function applyTheme(theme: Theme, persist = true): void {
  document.documentElement.setAttribute("data-theme", theme);
  if (!persist) return;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // sin storage: el tema vale solo para esta sesion
  }
}

export function initTheme(): void {
  applyTheme(getStoredTheme() ?? systemTheme(), false);
}

export function toggleTheme(): Theme {
  const next: Theme = currentTheme() === "dark" ? "light" : "dark";
  applyTheme(next);
  return next;
}
