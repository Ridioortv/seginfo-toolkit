// Tablero ejecutivo: tipos de la API y helpers puros (sin React).
import { t } from "../i18n";

export interface Delta { current: number | null; previous: number | null; change: number | null; change_pct: number | null }
export interface Msg { text: string; args: string[] }
export interface Attention { level: "critical" | "warning" | "info"; code: string; message: Msg; link: string }
export interface UnitRow { unit: string; assets: number; critical: number; high: number; medium: number; low: number; kev: number; score: number; share_pct: number }
export interface TopAsset { asset_id: string; hostname: string; known: boolean; business_unit: string; criticality: string; critical: number; high: number; medium: number; kev: number; score: number }

export interface ExecutiveSummary {
  generated_at: string; days: number; status: "stable" | "watch" | "attention";
  period: { from: string; to: string }; previous_period: { from: string; to: string };
  organization: { id: string; name: string };
  sources: Record<string, { ok: boolean; error: string }>;
  vulnerabilities?: {
    open_total: number; by_severity: Record<string, number>; critical_high: number; kev: number; oldest_critical_high_days: number; accepted_risk: number;
    created: Delta; remediated: Delta; created_critical_high: Delta; remediated_critical_high: Delta;
  };
  remediation?: {
    mttr_real_hours: number | null; mttr_declared_hours: number | null; gap_hours: number | null; false_closure_rate_pct: number | null;
    verified: number; failed: number; remediated_total: number; remediated_unverified: number;
  };
  exposure?: { by_business_unit: UnitRow[]; top_assets: TopAsset[]; total_score: number; unassigned_share_pct: number; units_defined: number; weights: Record<string, number> };
  compliance?: { score_verified: number | null; score_total: number | null; verified_controls: number; total_controls: number; previous_score_verified: number | null; change: number | null };
  cases?: { open: number; overdue: number; total: number; opened: Delta; resolved: Delta; mttr_hours: Delta; sla_met_pct: number | null; sla_measured: number };
  exceptions?: { pending: number; active: number; active_critical_or_high: number; expiring_soon: number };
  vendors?: { total: number; high_or_critical_risk: number; without_assessment_critical_or_high: number };
  drills?: { completed_total: number; days_since_last: number | null; last_score: number | null; median_ack_seconds: number | null };
  custody?: { ok: boolean; entries: number };
  attention: Attention[];
}

export interface TrendPoint {
  day: string; open_total: number | null; critical_high: number | null; kev: number | null; compliance: number | null;
  mttr_real_hours: number | null; exposure: number | null; exceptions_active: number | null;
}

export const STATUS_LABEL: Record<ExecutiveSummary["status"], string> = {
  stable: "Estable", watch: "A vigilar", attention: "Requiere atencion",
};
export const STATUS_HELP: Record<ExecutiveSummary["status"], string> = {
  stable: "Sin alertas que requieran una decision de la direccion.",
  watch: "Hay puntos que conviene atender en el corto plazo.",
  attention: "Hay puntos criticos que necesitan una decision.",
};
export const STATUS_BADGE: Record<ExecutiveSummary["status"], string> = {
  stable: "badge badge-success", watch: "badge badge-high", attention: "badge badge-critical",
};
export const LEVEL_BADGE: Record<Attention["level"], string> = {
  critical: "badge badge-critical", warning: "badge badge-high", info: "badge badge-neutral",
};
export const LEVEL_LABEL: Record<Attention["level"], string> = { critical: "Critico", warning: "Atencion", info: "Informativo" };
export const PERIODS = [7, 30, 90, 180, 365];

/** Mensaje de la API (plantilla con {0}, {1}... y sus valores aparte) en el idioma de la pantalla. */
export function fmtMsg(m: Msg): string {
  return t(m.text, ...m.args);
}

/** Cambio contra el periodo anterior: "+3 (+25%)" o "sin comparacion". */
export function changeText(d: Delta | undefined | null): string {
  if (!d || d.change === null) return t("sin comparacion");
  const sign = d.change > 0 ? "+" : "";
  const pct = d.change_pct === null ? "" : ` (${d.change_pct > 0 ? "+" : ""}${d.change_pct}%)`;
  return `${sign}${d.change}${pct}`;
}

/** "good" si el cambio es favorable. `goodWhen`: en los numeros de riesgo bajar es bueno; en lo remediado, subir. */
export function tone(change: number | null | undefined, goodWhen: "down" | "up"): "good" | "bad" | "neutral" {
  if (change === null || change === undefined || change === 0) return "neutral";
  return (change < 0) === (goodWhen === "down") ? "good" : "bad";
}

export function hoursText(h: number | null | undefined): string {
  if (h === null || h === undefined) return "-";
  if (h < 48) return t("{0} h", Math.round(h * 10) / 10);
  return t("{0} dias", Math.round((h / 24) * 10) / 10);
}

/** Puntos "x,y" de una linea de tendencia en un cuadro w x h; ignora los dias sin dato. Devuelve null si hay menos de dos puntos. */
export function sparkPoints(values: (number | null)[], w: number, h: number, pad = 4): string | null {
  const pts = values.map((v, i) => (v === null || v === undefined ? null : ([i, v] as const))).filter((p): p is readonly [number, number] => p !== null);
  if (pts.length < 2) return null;
  const ys = pts.map((p) => p[1]);
  const lo = Math.min(...ys, 0), hi = Math.max(...ys);
  const span = hi - lo || 1;
  const n = Math.max(values.length - 1, 1);
  return pts.map(([i, v]) => `${(pad + ((w - 2 * pad) * i) / n).toFixed(1)},${(h - pad - ((h - 2 * pad) * (v - lo)) / span).toFixed(1)}`).join(" ");
}
