import { useLangStore } from "./i18n/store";

// Los tests asumen la UI base en espanol, sin depender del idioma de la maquina donde corren.
useLangStore.setState({ lang: "es" });
