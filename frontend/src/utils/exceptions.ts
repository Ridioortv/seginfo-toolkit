// Excepciones de riesgo: tipos de la API y helpers puros (sin React).

export type ExceptionStatus = "pending" | "approved" | "rejected" | "withdrawn" | "revoked" | "expired" | "closed";

export const EXCEPTION_BADGE: Record<ExceptionStatus, string> = {
  pending: "badge badge-medium",
  approved: "badge badge-success",
  rejected: "badge badge-critical",
  withdrawn: "badge badge-neutral",
  revoked: "badge badge-critical",
  expired: "badge badge-neutral",
  closed: "badge badge-neutral",
};

export const EXCEPTION_LABEL: Record<ExceptionStatus, string> = {
  pending: "Pendiente de aprobacion",
  approved: "Vigente",
  rejected: "Rechazada",
  withdrawn: "Retirada",
  revoked: "Revocada",
  expired: "Vencida",
  closed: "Cerrada",
};

export interface RiskExceptionRow {
  id: string; vuln_id: string; vuln_title: string; severity: string; cve_id: string; status: ExceptionStatus; status_label: string;
  requested_by: string; requested_at: string; requested_days: number; decided_by: string; decided_at: string | null;
  expires_at: string | null; days_left: number | null; expiring_soon: boolean; ended_at: string | null; end_reason: string;
  max_days: number; justification?: string; compensating_controls?: string; decision_note?: string;
}

export interface ExceptionSummary {
  pending: number; active: number; active_critical_or_high: number; expiring_soon: number; expired_last_30_days: number;
  rejected_last_30_days: number; total: number; self_approval_allowed: boolean;
}

export const MAX_DAYS: Record<string, number> = { critical: 90, high: 180 };
export const MIN_DAYS = 7;

export function maxDays(severity: string): number {
  return MAX_DAYS[severity] ?? 365;
}

/** Alta y critica exigen controles compensatorios y pasan por una excepcion aprobada. */
export function needsException(severity: string, status: string): boolean {
  return (severity === "critical" || severity === "high") && status !== "accepted_risk";
}

export function canDecide(role: string, severity: string): boolean {
  return role === "admin" || (role === "soc_manager" && severity !== "critical");
}

/** Quien pidio no puede aprobar lo suyo (salvo que la instalacion lo permita). */
export function canApprove(row: Pick<RiskExceptionRow, "requested_by" | "severity" | "status">, me: string, role: string, selfAllowed: boolean): boolean {
  if (row.status !== "pending" || !canDecide(role, row.severity)) return false;
  return selfAllowed || row.requested_by.trim().toLowerCase() !== me.trim().toLowerCase();
}
