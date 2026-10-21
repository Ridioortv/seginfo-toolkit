import { translate } from "./translate";
import { useLangStore } from "./store";
import type { Lang } from "./languages";

/**
 * Traduce la UI en vivo. Toda la app esta escrita en espanol; en vez de
 * envolver miles de textos con una funcion, este observador recorre los nodos
 * de texto (y los atributos visibles: placeholder, title, aria-label, alt) y
 * los reemplaza por su traduccion del diccionario. Solo cambia el `data` del
 * nodo existente (nunca crea ni mueve nodos), asi que no interfiere con React.
 * Al cambiar de idioma la app se vuelve a montar (ver App.tsx) y el observador
 * traduce el arbol nuevo.
 */

const ATTRS = ["placeholder", "title", "aria-label", "alt"] as const;
const SKIP_SELECTOR = "script,style,textarea,code,pre,noscript,[translate='no']";

const lastWrittenText = new WeakMap<Node, string>();
const lastWrittenAttr = new WeakMap<Element, Map<string, string>>();

function inSkippedZone(el: Element | null): boolean {
  return !!el && !!el.closest(SKIP_SELECTOR);
}

function translateTextNode(node: Text, lang: Lang) {
  if (lastWrittenText.get(node) === node.data) return;
  if (inSkippedZone(node.parentElement)) return;
  const out = translate(node.data, lang);
  if (out !== node.data) {
    node.data = out;
    lastWrittenText.set(node, out);
  }
}

function translateAttrs(el: Element, lang: Lang, only?: string) {
  const names = only ? [only] : ATTRS;
  for (const name of names) {
    const value = el.getAttribute(name);
    if (!value) continue;
    if (lastWrittenAttr.get(el)?.get(name) === value) continue;
    if (inSkippedZone(el)) continue;
    const out = translate(value, lang);
    if (out !== value) {
      el.setAttribute(name, out);
      let m = lastWrittenAttr.get(el);
      if (!m) lastWrittenAttr.set(el, (m = new Map()));
      m.set(name, out);
    }
  }
  if (el instanceof HTMLInputElement && (el.type === "submit" || el.type === "button") && el.value) {
    const out = translate(el.value, lang);
    if (out !== el.value) el.value = out;
  }
}

export function translateTree(root: Node, lang: Lang) {
  if (root.nodeType === Node.TEXT_NODE) {
    translateTextNode(root as Text, lang);
    return;
  }
  if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_NODE) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  let n: Node | null = root.nodeType === Node.ELEMENT_NODE ? root : walker.nextNode();
  while (n) {
    if (n.nodeType === Node.TEXT_NODE) translateTextNode(n as Text, lang);
    else translateAttrs(n as Element, lang);
    n = walker.nextNode();
  }
}

let observer: MutationObserver | null = null;

function applyDocumentLang(lang: Lang) {
  document.documentElement.lang = lang;
}

export function startI18n() {
  if (observer || typeof document === "undefined") return;
  const run = () => translateTree(document.body, useLangStore.getState().lang);
  applyDocumentLang(useLangStore.getState().lang);
  run();
  observer = new MutationObserver((records) => {
    const lang = useLangStore.getState().lang;
    for (const r of records) {
      if (r.type === "characterData") translateTree(r.target, lang);
      else if (r.type === "attributes") translateAttrs(r.target as Element, lang, r.attributeName ?? undefined);
      else r.addedNodes.forEach((node) => translateTree(node, lang));
    }
  });
  observer.observe(document.body, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: [...ATTRS],
  });
  useLangStore.subscribe((state, prev) => {
    if (state.lang !== prev.lang) {
      applyDocumentLang(state.lang);
      // El arbol se remonta con la nueva clave de idioma; si algo quedo fuera de React se re-traduce igual.
      queueMicrotask(run);
    }
  });
}
