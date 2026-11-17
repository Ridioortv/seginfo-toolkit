// Consola multicliente: tipos de la API y helpers puros.
import type { Attention } from "./executive";

export type ClientStatus = "attention" | "watch" | "stable" | "unknown" | "suspended";

export interface ClientRow {
  id: string; name: string; is_active: boolean; users: number; subscription_expires_at: string | null;
  status: ClientStatus; error: string;
  sources_down?: string[]; assets?: number; exposure?: number | null; open_total?: number | null; critical_high?: number | null; kev?: number | null;
  oldest_critical_high_days?: number | null; cases_open?: number | null; cases_overdue?: number | null; cases_opened?: number | null;
  mttr_real_hours?: number | null; exceptions_active?: number | null; vendors_high_critical?: number | null;
  attention?: { critical: number; warning: number; info: number }; top_attention?: Attention[];
}

export interface PartnerOverview {
  generated_at: string; days: number; partner: { id: string; name: string };
  totals: { clients: number; active: number; by_status: Record<ClientStatus, number>; critical_high: number; kev: number; open_total: number; cases_open: number; cases_overdue: number; assets: number; users: number };
  clients: ClientRow[];
}

export const CLIENT_STATUS_LABEL: Record<ClientStatus, string> = {
  attention: "Requiere atencion", watch: "A vigilar", stable: "Estable", unknown: "Sin datos", suspended: "Suspendido",
};
export const CLIENT_STATUS_BADGE: Record<ClientStatus, string> = {
  attention: "badge badge-critical", watch: "badge badge-high", stable: "badge badge-success", unknown: "badge badge-neutral", suspended: "badge badge-neutral",
};

export function canEnter(c: Pick<ClientRow, "is_active">): boolean {
  return c.is_active;
}

/** Texto del vencimiento: "vence en 12 dias", "vencida", o vacio. */
export function expiryNote(iso: string | null, nowMs: number = Date.now()): { key: "expired" | "soon" | "ok" | "none"; days: number } {
  if (!iso) return { key: "none", days: 0 };
  const days = Math.ceil((new Date(iso).getTime() - nowMs) / 86_400_000);
  return days <= 0 ? { key: "expired", days: 0 } : days <= 7 ? { key: "soon", days } : { key: "ok", days };
}

/** Una cifra que puede faltar: si el cliente no se pudo leer se muestra "-" y no 0. */
export function figure(v: number | null | undefined): string {
  return v === null || v === undefined ? "-" : String(v);
}
