import { describe, expect, it } from "vitest";
import { translate, translateKey } from "./translate";
import { detectLang, LANGUAGES } from "./languages";
import en from "./dict/en";
import zh from "./dict/zh";
import ru from "./dict/ru";
import es from "./dict/es";

const PH = /\{\d+\}/g;
const placeholders = (s: string) => (s.match(PH) ?? []).sort().join(",");

describe("translate", () => {
  it("traduce textos exactos y conserva los espacios del borde", () => {
    expect(translate("Guardando...", "en")).toBe("Saving...");
    expect(translate("  Guardando...\n", "ru")).toBe("  " + ru["Guardando..."] + "\n");
    expect(translate("Guardando...", "zh")).toBe(zh["Guardando..."]);
  });

  it("colapsa espacios internos como lo hace JSX", () => {
    expect(translate("Cargar\n     reglas recomendadas", "en")).toBe(en["Cargar reglas recomendadas"]);
    expect(translate("Cargar   reglas recomendadas", "en")).toBe(en["Cargar reglas recomendadas"]);
  });

  it("devuelve el texto tal cual si no hay traduccion o el idioma es espanol", () => {
    expect(translate("texto que no existe en el diccionario", "en")).toBe("texto que no existe en el diccionario");
    expect(translate("Guardando...", "es")).toBe("Guardando...");
  });

  it("resuelve plantillas con valores dinamicos", () => {
    expect(translate("Hola, manu", "en")).toBe("Hello, manu");
    expect(translate("3 escaneos en curso", "en")).toBe(en["{0} escaneos en curso"].replace("{0}", "3"));
    expect(translate("Reconocido por ana@x.com", "ru")).toBe(ru["Reconocido por {0}"].replace("{0}", "ana@x.com"));
  });

  it("traduce los valores internos capturados cuando son claves (ej. 'corriendo')", () => {
    expect(translate("corriendo hace 5s", "en")).toBe("running for 5s");
    expect(translate("corriendo hace 5s -- tarda mas de lo usual", "en")).toContain("running for 5s");
    expect(translate("corriendo hace 5s -- tarda mas de lo usual", "en")).not.toContain("tarda");
  });

  it("las plantillas aceptan valores vacios (ej. el sufijo opcional '(con filtro aplicado)')", () => {
    expect(translate("Mostrando 2 de 5 imagen(es).", "en")).toBe(en["Mostrando {0} de {1} imagen(es){2}."].replace("{0}", "2").replace("{1}", "5").replace("{2}", ""));
    const withFilter = translate("Mostrando 2 de 5 imagen(es) (con filtro aplicado).", "en");
    expect(withFilter).toContain(" " + en["(con filtro aplicado)"]);
  });

  it("las variantes en ingles de los enums se muestran en espanol en modo es", () => {
    expect(translate("in_progress", "es")).toBe(es["in_progress"]);
  });

  it("translateKey sustituye argumentos y cae al espanol si no hay traduccion", () => {
    expect(translateKey('Desconectar la cuenta "{0}"? Se van a dejar de sincronizar sus recursos.', "en", "prod")).toContain('"prod"');
    expect(translateKey("Hola {0}", "es", "Ana")).toBe("Hola Ana");
    expect(translateKey("Sin traduccion {0}", "zh", "x")).toBe("Sin traduccion x");
  });
});

describe("diccionarios", () => {
  for (const [name, dict] of [["en", en], ["zh", zh], ["ru", ru], ["es", es]] as const) {
    it(`${name}: cada traduccion conserva los mismos {n} que la clave y no esta vacia`, () => {
      for (const [key, value] of Object.entries(dict)) {
        expect(value.trim(), `${name}: "${key}" vacio`).not.toBe("");
        expect(placeholders(value), `${name}: placeholders de "${key}"`).toBe(placeholders(key));
      }
    });
  }

  it("en, zh y ru cubren las mismas claves principales", () => {
    const base = Object.keys(en).filter((k) => /[a-z]{4,}/.test(k));
    const missingZh = base.filter((k) => !(k in zh) && zh[k] !== k);
    const missingRu = base.filter((k) => !(k in ru) && ru[k] !== k);
    // Un par de claves pueden coincidir con el original (terminos tecnicos); casi todas deben estar.
    expect(missingZh.length).toBeLessThan(base.length * 0.05);
    expect(missingRu.length).toBeLessThan(base.length * 0.05);
  });
});

describe("detectLang", () => {
  it("prioriza el idioma guardado", () => {
    expect(detectLang("ru", ["en-US"])).toBe("ru");
  });
  it("usa el idioma del navegador si no hay guardado", () => {
    expect(detectLang(null, ["zh-CN", "en"])).toBe("zh");
    expect(detectLang(null, "en-GB")).toBe("en");
    expect(detectLang(null, ["fr-FR", "ru"])).toBe("ru");
  });
  it("cae en espanol si no reconoce nada", () => {
    expect(detectLang(null, ["fr-FR"])).toBe("es");
    expect(detectLang("xx", undefined)).toBe("es");
  });
  it("expone los 4 idiomas", () => {
    expect(LANGUAGES.map((l) => l.code)).toEqual(["es", "en", "zh", "ru"]);
  });
});

describe("plantillas", () => {
  it("ninguna clave tiene dos {n} pegados (la expresion regular no podria repartirlos)", () => {
    for (const dict of [en, zh, ru, es]) {
      for (const key of Object.keys(dict)) expect(key, key).not.toMatch(/\}\{\d/);
    }
  });
});
