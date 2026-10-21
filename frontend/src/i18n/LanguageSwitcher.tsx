import { useEffect, useRef, useState } from "react";
import Icon from "../components/Icon";
import { LANGUAGES } from "./languages";
import { useLangStore } from "./store";

/**
 * Menu chico para cambiar el idioma (ES / EN / 中文 / RU). Va en la barra
 * superior de la app y, flotando, en la pantalla de login. Los nombres de los
 * idiomas se muestran siempre en su propio idioma (translate="no") para que
 * alguien que no entiende el idioma actual igual pueda encontrar el suyo.
 */
export default function LanguageSwitcher({ floating = false }: { floating?: boolean }) {
  const lang = useLangStore((s) => s.lang);
  const setLang = useLangStore((s) => s.setLang);
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const current = LANGUAGES.find((l) => l.code === lang) ?? LANGUAGES[0];

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className={"lang-switcher" + (floating ? " lang-switcher-floating" : "")} ref={rootRef}>
      <button
        type="button"
        className="lang-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Idioma"
        title="Idioma"
        onClick={() => setOpen((o) => !o)}
      >
        <Icon name="surface" />
        <span translate="no">{current.short}</span>
      </button>
      {open && (
        <ul className="lang-menu" role="menu" translate="no">
          {LANGUAGES.map((l) => (
            <li key={l.code} role="none">
              <button
                type="button"
                role="menuitemradio"
                aria-checked={l.code === lang}
                lang={l.code}
                className={"lang-item" + (l.code === lang ? " lang-item-active" : "")}
                onClick={() => {
                  setLang(l.code);
                  setOpen(false);
                }}
              >
                <span>{l.label}</span>
                {l.code === lang && <Icon name="check" />}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
