/**
 * Calcula el porcentaje de progreso de lectura de la guia de Ayuda
 * (cuantas secciones del tutorial interactivo marco el usuario como
 * "leidas" sobre el total de secciones visibles para su rol).
 *
 * Extraida como funcion pura para poder testearla sin renderizar
 * Help.tsx ni depender de localStorage.
 */
export function progressPercent(total: number, completed: number): number {
  if (total <= 0) return 0;
  const clamped = Math.min(Math.max(completed, 0), total);
  return Math.round((clamped / total) * 100);
}

/**
 * Filtra los topics de ayuda que coinciden con una busqueda de texto libre,
 * comparando (sin importar mayusculas/acentos de capitalizacion) contra el
 * titulo, la bajada, la descripcion general y el texto de cada paso.
 */
export interface SearchableHelpTopic {
  id: string;
  label: string;
  tagline: string;
  overview: string;
  steps: { title: string; body: string }[];
}

export function filterHelpTopics<T extends SearchableHelpTopic>(topics: T[], query: string): T[] {
  const q = query.trim().toLowerCase();
  if (!q) return topics;
  return topics.filter((t) => {
    const haystack = [
      t.label,
      t.tagline,
      t.overview,
      ...t.steps.flatMap((s) => [s.title, s.body]),
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(q);
  });
}
