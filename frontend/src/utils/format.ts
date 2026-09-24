/**
 * Formatea una fecha ISO (o null/undefined, comun cuando todavia no se
 * conoce -- ej. una organizacion sin `subscription_expires_at`) a
 * dd/mm/aaaa en es-AR, o "--" cuando no hay fecha. Extraida de Billing.tsx
 * como funcion pura para poder testearla sin renderizar el componente.
 */
export function formatDate(iso: string | undefined | null): string {
  if (!iso) return "--";
  return new Date(iso).toLocaleDateString("es-AR");
}
