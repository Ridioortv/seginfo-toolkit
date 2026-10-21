import type { Lang } from "./languages";
import en from "./dict/en";
import zh from "./dict/zh";
import ru from "./dict/ru";
import es from "./dict/es";

/**
 * Motor de traduccion. El texto fuente de toda la app esta en espanol y es la
 * CLAVE del diccionario: translate("Guardar", "en") -> "Save". Las claves con
 * {0}, {1}... son plantillas para texto dinamico ("Hola, {0}"): se compilan a
 * una expresion regular, y los valores capturados se copian (traducidos si
 * ellos mismos son una clave) en la plantilla del idioma destino.
 */

type Pattern = { re: RegExp; template: string; weight: number };
type Compiled = { exact: Map<string, string>; patterns: Pattern[]; cache: Map<string, string | null> };

const PLACEHOLDER = /\{(\d+)\}/g;
const HAS_LETTER = /[A-Za-zÀ-ÿА-яЁё一-鿿]/;

export function normalize(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function compile(dict: Record<string, string>): Compiled {
  const exact = new Map<string, string>();
  const patterns: Pattern[] = [];
  for (const [key, value] of Object.entries(dict)) {
    const nk = normalize(key);
    exact.set(nk, value); // tambien las plantillas: translateKey las busca por clave
    if (!/\{\d+\}/.test(nk)) continue;
    const literals = nk.split(PLACEHOLDER).filter((_, i) => i % 2 === 0);
    if (!literals.some((l) => HAS_LETTER.test(l))) continue; // "{0}" solo: demasiado ambiguo
    const order: number[] = [];
    const source = nk
      .split(PLACEHOLDER)
      .map((part, i) => {
        if (i % 2 === 1) {
          order.push(Number(part));
          return "([\\s\\S]*?)";
        }
        return escapeRe(part);
      })
      .join("");
    // Los grupos se numeran por orden de aparicion; {n} del destino se mapea por indice n.
    const groupOfPlaceholder = new Map<number, number>();
    order.forEach((n, groupIdx) => groupOfPlaceholder.set(n, groupIdx));
    const template = value.replace(PLACEHOLDER, (_m, n) => `\u0000${groupOfPlaceholder.get(Number(n)) ?? Number(n)}\u0000`);
    patterns.push({ re: new RegExp(`^${source}$`), template, weight: literals.join("").length });
  }
  patterns.sort((a, b) => b.weight - a.weight);
  return { exact, patterns, cache: new Map() };
}

const compiled: Partial<Record<Lang, Compiled>> = {};
const SOURCES: Record<Lang, Record<string, string>> = { es, en, zh, ru };

function getCompiled(lang: Lang): Compiled {
  return (compiled[lang] ??= compile(SOURCES[lang]));
}

function lookup(core: string, lang: Lang, depth = 0): string | null {
  const c = getCompiled(lang);
  const hit = c.exact.get(core);
  if (hit !== undefined) return hit;
  if (c.cache.has(core)) return c.cache.get(core)!;
  let result: string | null = null;
  if (depth < 2) {
    for (const p of c.patterns) {
      const m = p.re.exec(core);
      if (!m) continue;
      result = p.template.replace(/\u0000(\d+)\u0000/g, (_x, g) => {
        const captured = m[Number(g) + 1] ?? "";
        const edges = /^(\s*)([\s\S]*?)(\s*)$/.exec(captured);
        const core = normalize(edges?.[2] ?? "");
        const inner = core ? lookup(core, lang, depth + 1) : null;
        return inner === null || !edges ? captured : edges[1] + inner + edges[3];
      });
      break;
    }
  }
  if (c.cache.size > 5000) c.cache.clear();
  c.cache.set(core, result);
  return result;
}

/** Traduce un texto de la UI (conserva los espacios del borde). Si no hay traduccion, lo devuelve igual. */
export function translate(text: string, lang: Lang): string {
  if (lang === "es" && getCompiled("es").exact.size === 0) return text;
  const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(text);
  if (!m) return text;
  const core = normalize(m[2]);
  if (!core) return text;
  const out = lookup(core, lang);
  return out === null ? text : m[1] + out + m[3];
}

/**
 * Traduccion imperativa para textos que no pasan por el DOM (ej. window.confirm).
 * `key` es el texto en espanol con {0}, {1}... y `args` los valores.
 */
export function translateKey(key: string, lang: Lang, ...args: (string | number)[]): string {
  const base = lang === "es" ? key : (getCompiled(lang).exact.get(normalize(key)) ?? key);
  return base.replace(PLACEHOLDER, (_m, n) => String(args[Number(n)] ?? ""));
}
