/**
 * Un caso esta "vencido" (breached) cuando tiene una fecha limite de SLA,
 * esa fecha ya paso, y el caso todavia no se resolvio/cerro -- un caso ya
 * resuelto despues de vencido no debe seguir marcandose como vencido en la
 * UI (ver src/pages/Cases.tsx).
 *
 * `now` se recibe como parametro (en vez de llamar a `new Date()` aca
 * adentro) para que la funcion sea pura y facil de testear con fechas
 * fijas.
 */
export function isSlaBreached(
  slaDueAt: string | null,
  status: string,
  now: string = new Date().toISOString()
): boolean {
  if (!slaDueAt) return false;
  if (status === "resolved" || status === "closed") return false;
  return slaDueAt < now;
}
