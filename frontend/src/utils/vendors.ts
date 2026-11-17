// Riesgo de proveedores: tipos de la API y helpers puros (sin React).

export type VendorLevel = "critical" | "high" | "medium" | "low" | "unassessed" | "stale";
export type Criticality = "critical" | "high" | "medium" | "low";

export const LEVEL_BADGE: Record<VendorLevel, string> = {
  critical: "badge badge-critical",
  high: "badge badge-high",
  medium: "badge badge-medium",
  low: "badge badge-success",
  unassessed: "badge badge-neutral",
  stale: "badge badge-neutral",
};

export const LEVEL_LABEL: Record<VendorLevel, string> = {
  critical: "Critico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  unassessed: "Sin evaluar",
  stale: "Evaluacion vencida",
};

export const CRITICALITY_LABEL: Record<Criticality, string> = { critical: "Critico", high: "Alto", medium: "Medio", low: "Bajo" };
export const CRITICALITY_HELP: Record<Criticality, string> = {
  critical: "Si falla, el negocio se frena o se filtran datos sensibles",
  high: "Su falla afecta a clientes o a una operacion importante",
  medium: "Su falla molesta pero se puede esquivar",
  low: "Su falla casi no se nota",
};

export const DATA_TYPE_LABEL: Record<string, string> = {
  personal: "Datos personales",
  financial: "Datos financieros",
  health: "Datos de salud",
  credentials: "Credenciales o accesos",
  intellectual_property: "Propiedad intelectual",
  none: "No maneja datos",
};

export const EVIDENCE_STATUS_BADGE: Record<string, string> = {
  vigente: "badge badge-success",
  por_vencer: "badge badge-medium",
  vencida: "badge badge-critical",
};
export const EVIDENCE_STATUS_LABEL: Record<string, string> = { vigente: "Vigente", por_vencer: "Por vencer", vencida: "Vencida" };

export const ASSESSMENT_STATUS_LABEL: Record<string, string> = {
  sent: "Pendiente de respuesta", completed: "Respondido", cancelled: "Cancelado", expired: "Vencido",
};

export const ANSWER_LABEL: Record<string, string> = { yes: "Si", partial: "Parcial", no: "No", na: "No aplica" };

export interface VendorRisk {
  level: VendorLevel;
  level_label: string;
  index: number | null;
  effective_score: number | null;
  evidence_bonus: number;
  stale: boolean;
}

export interface VendorEvidence {
  id: string; kind: string; kind_label: string; title: string; issued_at: string | null; valid_until: string | null;
  status: "vigente" | "por_vencer" | "vencida"; reference_url: string; document_sha256: string; note: string;
  added_by: string; added_at: string;
}

export interface VendorAssessment {
  id: string; status: "sent" | "completed" | "cancelled" | "expired"; created_by: string; created_at: string; expires_at: string;
  completed_at: string | null; respondent_name: string; respondent_email: string; score_base: number | null;
  score_detail: { base?: number; knockouts?: string[]; knockout_penalty?: number; domains?: Record<string, number> };
  answers?: { id: string; domain: string; text: string; knockout: boolean; answer: string; comment: string }[];
}

export interface Vendor {
  id: string; name: string; domain: string; criticality: Criticality; criticality_label: string; service_description: string;
  data_types: string[]; owner: string; contact_email: string; status: "active" | "offboarded"; contract_end: string | null;
  notes: string; created_at: string; created_by: string; risk: VendorRisk; last_assessment_at: string | null;
  pending_assessment: boolean; evidence_counts: { vigente: number; por_vencer: number; vencida: number };
  contract_expiring: boolean; evidence?: VendorEvidence[]; assessments?: VendorAssessment[];
}

export interface VendorSummary {
  total: number; by_level: Record<VendorLevel, number>; critical_vendors: number; high_or_critical_risk: number;
  without_assessment_critical_or_high: number; pending_questionnaires: number; expired_evidence: number;
  expiring_evidence: number; contracts_expiring: number;
}

export interface PublicQuestion { id: string; domain: string; text: string }
export interface PublicAssessment {
  state: "sent" | "completed" | "cancelled" | "expired"; vendor_name: string; expires_at: string | null;
  questions: PublicQuestion[]; answers_options: string[];
}

/** Link que se le manda al proveedor, armado con el origen desde el que se usa TERO. */
export function assessmentLink(origin: string, path: string): string {
  return `${origin.replace(/\/+$/, "")}${path}`;
}

/** Agrupa las preguntas por dominio conservando el orden. */
export function groupByDomain<T extends { domain: string }>(items: T[]): [string, T[]][] {
  const out: [string, T[]][] = [];
  for (const item of items) {
    const last = out[out.length - 1];
    if (last && last[0] === item.domain) last[1].push(item);
    else out.push([item.domain, [item]]);
  }
  return out;
}

export function unanswered(questions: PublicQuestion[], answers: Record<string, string>): number {
  return questions.filter((q) => !answers[q.id]).length;
}

/** "2027-01-31" (campo date) -> ISO a mediodia UTC, para que ningun huso horario lo mueva de dia. */
export function dateToIso(value: string): string | null {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T12:00:00Z` : null;
}
