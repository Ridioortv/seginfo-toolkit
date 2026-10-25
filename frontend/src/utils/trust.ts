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

export type SovereigntyVerdict = "no_data" | "unexpected" | "controlled" | "isolated_unverified" | "isolated_verified";

export interface SovereigntyDestination {
  service: string;
  host: string;
  kind: string;
  count: number;
  blocked: number;
  first_seen: string;
  last_seen: string;
  classification: "catalogado" | "configurado" | "no_catalogado";
  purposes: string[];
  recent: boolean;
  catalog: { id: string; category: string; purpose: string; sends: string; optional: boolean; offline: string } | null;
}

export interface SovereigntyService {
  service: string;
  isolated: boolean;
  instance: string;
  allowlist: string[];
  last_seen: string;
  reporting: boolean;
  configurable: string;
}

export interface ProbeResult {
  target: string;
  kind: string;
  reachable: boolean;
  detail: string;
  informational: boolean;
}

export interface SovereigntyProbe {
  id: string;
  created_at: string;
  actor: string;
  reachable: number;
  total: number;
  results: ProbeResult[];
  verdict?: SovereigntyVerdict;
}

export interface SovereigntyStatus {
  verdict: SovereigntyVerdict;
  notes: { text: string; args: string[] }[];
  summary: {
    services_expected: number;
    services_reporting: number;
    services_missing: string[];
    isolated_services: number;
    external_destinations: number;
    unknown_destinations: number;
    blocked_attempts: number;
  };
  services: SovereigntyService[];
  destinations: SovereigntyDestination[];
  probe: SovereigntyProbe | null;
  network_exceptions: string[];
  limits: string[];
}

export const VERDICT_TEXT: Record<SovereigntyVerdict, { title: string; detail: string; tone: "ok" | "warn" | "bad" | "info" }> = {
  isolated_verified: {
    title: "Aislado y verificado",
    detail: "Todos los servicios estan en modo aislado y la prueba de red no pudo salir a internet.",
    tone: "ok",
  },
  isolated_unverified: {
    title: "Aislado por la aplicacion, falta confirmar la red",
    detail: "Todos los servicios bloquean las salidas, pero la red todavia no demostro que no se pueda salir.",
    tone: "warn",
  },
  controlled: {
    title: "Con salidas controladas",
    detail: "TERO habla con internet solo con destinos conocidos. Abajo ves cuales, para que y que datos viajan.",
    tone: "info",
  },
  unexpected: {
    title: "Hay salidas no catalogadas",
    detail: "Algun servicio hablo con un destino externo que no esta en el catalogo. Revisalo primero.",
    tone: "bad",
  },
  no_data: {
    title: "Todavia sin datos",
    detail: "Los servicios informan cada minuto; si despues de unos minutos sigue vacio, revisa que case-service este activo.",
    tone: "info",
  },
};

export const CLASSIFICATION_LABEL: Record<string, string> = {
  catalogado: "Conocido",
  configurado: "Configurado por un administrador",
  no_catalogado: "No catalogado",
};

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
  "vuln.closure_requested": "Re-escaneo de verificacion pedido",
  "vuln.closure_verified": "Cierre verificado",
  "vuln.closure_failed": "Cierre no verificado",
  "sovereignty.mode_changed": "Modo de soberania",
  "sovereignty.probe": "Prueba de salida a internet",
  "sovereignty.attestation": "Atestado de soberania firmado",
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
    case "vuln.closure_requested":
    case "vuln.closure_verified":
    case "vuln.closure_failed":
      return `${s("title")}${s("from") ? `: ${st(s("from"))} → ${st(s("to"))}` : ""}`;
    case "sovereignty.probe":
      return tr("{0} de {1} destinos alcanzables", s("reachable") || "0", s("total") || "0");
    case "sovereignty.mode_changed":
      return `${s("service")}: ${p.isolated_after ? tr("modo aislado activado") : tr("modo aislado desactivado")}`;
    case "sovereignty.attestation":
      return s("verdict");
    default:
      return JSON.stringify(p).slice(0, 120);
  }
}

export function shortHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 12)}…` : hash;
}

export type ClosureState = "" | "pending" | "verified" | "failed" | "inconclusive" | "unsupported";

export interface ClosureVuln {
  id: string;
  title: string;
  cve_id: string | null;
  severity: string;
  status: string;
  asset_id: string | null;
  remediated_at: string | null;
  verified_at: string | null;
  created_at: string;
  closure_status: ClosureState;
  closure_detail: string;
  closure_scan_job_id: string | null;
  closure_checked_at: string | null;
}

export interface ClosureStats {
  counts: Record<string, number>;
  remediated_total: number;
  remediated_unverified: number;
  mttr_declared_hours: number | null;
  mttr_real_hours: number | null;
  false_closure_rate_pct: number | null;
  by_severity: Record<string, { verified: number; failed: number; pending: number; unverified: number; mttr_real_hours: number | null; mttr_declared_hours: number | null }>;
}

export const CLOSURE_LABEL: Record<string, string> = {
  "": "Sin verificar",
  pending: "En verificacion",
  verified: "Verificado",
  failed: "Cierre fallido (reabierta)",
  inconclusive: "Sin concluir",
  unsupported: "No verificable",
};

export const CLOSURE_BADGE: Record<string, string> = {
  "": "badge badge-neutral",
  pending: "badge badge-medium",
  verified: "badge badge-success",
  failed: "badge badge-critical",
  inconclusive: "badge badge-medium",
  unsupported: "badge badge-neutral",
};

/** Horas -> texto corto: "26.5 h" o "2.3 d" (desde 48 h). */
export function formatHours(hours: number | null | undefined): string {
  if (hours === null || hours === undefined) return "-";
  if (hours < 48) return `${Math.round(hours * 10) / 10} h`;
  return `${Math.round((hours / 24) * 10) / 10} d`;
}

// ---------------- Cumplimiento con evidencia viva ----------------

export type ControlStatus =
  | "cumple" | "parcial" | "no_cumple" | "declarado_si" | "declarado_parcial" | "declarado_no" | "pendiente" | "vencido" | "sin_datos";

export interface Msg { text: string; args: string[] }

export interface ComplianceDeclaration {
  answer: "yes" | "partial" | "no";
  note: string;
  declared_by: string;
  declared_at: string;
  valid_until: string | null;
  expired: boolean;
}

export interface ComplianceControl {
  id: string;
  area: string;
  area_label: string;
  title: string;
  why: string;
  refs: string[];
  mode: "auto" | "manual";
  status: ControlStatus;
  basis: "verificado" | "declarado" | "ninguno";
  summary: Msg;
  evidence: { label: string; value: string; source: string }[];
  declaration: ComplianceDeclaration | null;
}

export interface ComplianceQuestion {
  id: string;
  text: string;
  answer: "yes" | "partial" | "no" | "pending";
  controls: { id: string; title: string; status: ControlStatus; basis: string; summary: Msg }[];
}

export interface ComplianceHistoryPoint {
  id: string;
  created_at: string;
  score_verified: number | null;
  score_total: number | null;
}

export interface ComplianceStatus {
  evaluated_at: string;
  disclaimer: string;
  summary: {
    score_verified: number | null;
    verified_controls: number;
    automatic_controls: number;
    score_total: number | null;
    total_controls: number;
    counts: Record<string, number>;
    by_area: Record<string, { label: string; total: number; score: number }>;
  };
  controls: ComplianceControl[];
  questionnaire: ComplianceQuestion[];
  history: ComplianceHistoryPoint[];
}

export const CONTROL_STATUS_LABEL: Record<ControlStatus, string> = {
  cumple: "Cumple",
  parcial: "Parcial",
  no_cumple: "No cumple",
  declarado_si: "Declarado: si",
  declarado_parcial: "Declarado: parcial",
  declarado_no: "Declarado: no",
  pendiente: "Pendiente de declarar",
  vencido: "Declaracion vencida",
  sin_datos: "Sin datos",
};

export const CONTROL_STATUS_BADGE: Record<ControlStatus, string> = {
  cumple: "badge badge-success",
  parcial: "badge badge-medium",
  no_cumple: "badge badge-critical",
  declarado_si: "badge badge-success",
  declarado_parcial: "badge badge-medium",
  declarado_no: "badge badge-critical",
  pendiente: "badge badge-neutral",
  vencido: "badge badge-medium",
  sin_datos: "badge badge-neutral",
};

export const BASIS_LABEL: Record<string, string> = {
  verificado: "Verificado por TERO",
  declarado: "Declarado por una persona",
  ninguno: "-",
};

export const ANSWER_LABEL: Record<string, string> = { yes: "Si", partial: "Parcial", no: "No", pending: "Sin responder" };
export const ANSWER_BADGE: Record<string, string> = {
  yes: "badge badge-success", partial: "badge badge-medium", no: "badge badge-critical", pending: "badge badge-neutral",
};

/** Los que hay que mirar: no cumple, parcial, sin declarar, vencido o sin datos. */
export function needsAction(c: Pick<ComplianceControl, "status">): boolean {
  return !["cumple", "declarado_si"].includes(c.status);
}

/** Se puede declarar a mano un control manual, o uno automatico al que TERO no le pudo ver datos. */
export function canDeclare(c: Pick<ComplianceControl, "mode" | "status" | "basis">): boolean {
  return c.mode === "manual" || c.status === "sin_datos" || c.basis === "declarado";
}

/** Puntos de una linea (SVG) para el historial: 0-100 en vertical, los vacios se saltean. */
export function sparkPoints(history: ComplianceHistoryPoint[], key: "score_verified" | "score_total", w: number, h: number): string {
  if (history.length === 0) return "";
  const step = history.length > 1 ? w / (history.length - 1) : 0;
  return history
    .map((p, i) => (p[key] === null ? null : `${Math.round(i * step * 10) / 10},${Math.round((h - (p[key] as number) / 100 * h) * 10) / 10}`))
    .filter((x): x is string => x !== null)
    .join(" ");
}
