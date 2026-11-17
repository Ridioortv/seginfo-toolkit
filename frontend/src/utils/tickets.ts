// Tickets vinculados (Jira / ServiceNow): tipos de la API y helpers puros.

export type TicketState = "open" | "resolved" | "closed_no_fix" | "simulated";

export interface TicketLink {
  id: string; connector_id: string; connector_name: string; provider: "jira" | "servicenow"; subject_type: "vulnerability" | "case";
  subject_id: string; subject_title: string; external_key: string; external_url: string; state: TicketState; external_status: string;
  applied: boolean; applied_note: string; last_error: string; created_by: string; created_at: string | null;
  last_synced_at: string | null; resolved_at: string | null;
}

export const STATE_LABEL: Record<TicketState, string> = {
  open: "Abierto", resolved: "Resuelto", closed_no_fix: "Cerrado sin corregir", simulated: "Simulado (modo de prueba)",
};
export const STATE_BADGE: Record<TicketState, string> = {
  open: "badge badge-medium", resolved: "badge badge-success", closed_no_fix: "badge badge-high", simulated: "badge badge-neutral",
};
export const PROVIDER_LABEL: Record<string, string> = { jira: "Jira", servicenow: "ServiceNow" };

/** Hay un ticket que sigue su curso (no hace falta abrir otro). */
export function hasActiveTicket(links: TicketLink[]): boolean {
  return links.some((l) => l.state === "open" || l.state === "simulated");
}

/** Texto de error de la API al crear un vinculo (puede venir como texto o como {message, ...}). */
export function ticketErrorText(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object" && "message" in detail) return String((detail as { message: unknown }).message);
  return fallback;
}

export interface TicketingConfigInput {
  provider: "jira" | "servicenow"; baseUrl: string; email: string; username: string; secret: string; projectKey: string; issueType: string;
  table: string; priorities: Record<string, string>; notifyChannelIds: string[];
}

/** Config que se manda a la API segun el proveedor (solo lo que corresponde, sin campos vacios). */
export function buildTicketingConfig(f: TicketingConfigInput): Record<string, unknown> {
  const notify = f.notifyChannelIds.length ? { notify_channel_ids: f.notifyChannelIds } : {};
  if (f.provider === "servicenow") {
    return { provider: "servicenow", base_url: f.baseUrl.trim(), username: f.username.trim(), api_token: f.secret, table: f.table.trim() || "incident", ...notify };
  }
  const priority_map = Object.fromEntries(Object.entries(f.priorities).filter(([, v]) => v.trim()));
  return { provider: "jira", base_url: f.baseUrl.trim(), email: f.email.trim(), api_token: f.secret, project_key: f.projectKey.trim(),
    issue_type: f.issueType.trim() || "Task", priority_map, ...notify };
}

/** URL completa del webhook entrante a partir del path que devuelve la API y la direccion publica de integration-service. */
export function webhookUrl(base: string, path: string): string {
  return `${base.replace(/\/+$/, "")}${path}`;
}
