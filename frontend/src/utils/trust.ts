// Confianza y evidencia: tipos de la API y helpers puros (sin React) para la cadena de custodia.

export interface CustodyStatus {
  entries: number;
  head_hash: string;
  public_key: string;
  key_fingerprint: string;
  key_derived_from_jwt: boolean;
  algorithm: string;
}

export interface CustodyEntryOut {
  seq: number;
  ts: string;
  event_type: string;
  actor: string;
  source: string;
  subject_type: string;
  subject_id: string;
  refs: string[];
  payload: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
  signature: string;
}

export interface CustodyPage {
  total: number;
  items: CustodyEntryOut[];
}

export interface CustodyVerify {
  ok: boolean;
  entries: number;
  head_hash: string;
  broken_at_seq: number | null;
  reason: string;
  anchor_checked: boolean;
}

export interface CustodyAnchor {
  entries: number;
  head_hash: string;
  generated_at: string;
  signature: string;
}

export const CUSTODY_EVENT_LABEL: Record<string, string> = {
  "case.created": "Caso creado",
  "case.status_changed": "Caso: cambio de estado",
  "case.updated": "Caso modificado",
  "case.note_added": "Nota en el caso",
  "case.imported": "Caso importado de SOAR",
  "alert.created": "Alerta generada",
  "alert.status_changed": "Alerta: cambio de estado",
  "soar.playbook_run": "Playbook ejecutado",
  "scan.completed": "Escaneo completado",
  "scan.failed": "Escaneo fallido",
  "vuln.status_changed": "Vulnerabilidad: cambio de estado",
  "vuln.closure_verified": "Cierre verificado",
  "vuln.closure_failed": "Cierre no verificado",
  "sovereignty.mode_changed": "Modo de soberania",
  "drill.completed": "Simulacro completado",
  "compliance.snapshot": "Foto de cumplimiento",
  "evidence.exported": "Paquete de evidencia exportado",
};

export const STATE_LABEL: Record<string, string> = {
  open: "Abierto",
  in_progress: "En curso",
  resolved: "Resuelto",
  closed: "Cerrado",
  new: "Nueva",
  acknowledged: "Reconocida",
  confirmed: "Confirmada",
  false_positive: "Falso positivo",
  accepted_risk: "Riesgo aceptado",
  remediated: "Remediada",
  completed: "Completado",
  failed: "Fallido",
};

export type Translator = (key: string, ...args: (string | number)[]) => string;
const plain: Translator = (key, ...args) => key.replace(/\{(\d+)\}/g, (_m, n) => String(args[Number(n)] ?? ""));

/** Resumen corto y legible del detalle de un evento de la cadena. */
export function summarizeCustody(eventType: string, p: Record<string, unknown>, tr: Translator = plain): string {
  const s = (k: string) => (p[k] === undefined || p[k] === null ? "" : String(p[k]));
  const st = (v: string) => (v ? tr(STATE_LABEL[v] ?? v) : "?");
  const caseTitle = ((p.case ?? {}) as Record<string, unknown>).title;
  const title = caseTitle ? String(caseTitle) : "";
  switch (eventType) {
    case "case.created":
    case "case.imported":
    case "case.updated":
    case "evidence.exported":
      return title || s("case_id");
    case "case.status_changed":
      return `${title ? `${title}: ` : ""}${st(s("from"))} → ${st(s("to"))}`;
    case "case.note_added":
      return [title, s("notes").slice(0, 80)].filter(Boolean).join(" · ");
    case "alert.created":
      return [s("rule"), s("severity"), s("host") || s("source_ip")].filter(Boolean).join(" · ");
    case "alert.status_changed":
      return `${s("rule")}: ${st(s("from"))} → ${st(s("to"))}`;
    case "soar.playbook_run":
      return `${s("playbook")} (${st(s("status"))})`;
    case "scan.completed":
    case "scan.failed":
      return `${s("scanner")} · ${s("target")} · ${tr("{0} hallazgos", s("findings") || "0")}`;
    case "vuln.status_changed":
    case "vuln.closure_verified":
    case "vuln.closure_failed":
      return `${s("title")}${s("from") ? `: ${st(s("from"))} → ${st(s("to"))}` : ""}`;
    default:
      return JSON.stringify(p).slice(0, 120);
  }
}

export function shortHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 12)}…` : hash;
}
