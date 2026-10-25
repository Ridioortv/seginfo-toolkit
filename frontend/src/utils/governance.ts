// Gobernanza de codigo con IA: tipos de la API (coderepo-service /governance/*), etiquetas y helpers
// puros (sin React) para poder probarlos con vitest.

export type Origin = "human" | "ai" | "mixed";
export type GateStatus = "passed" | "blocked" | "observed_fail";
export type Severity = "critical" | "high" | "medium" | "low";

export interface GovFinding {
  source: string;
  rule_id: string;
  severity: string;
  description: string;
  file: string;
  line: number | null;
  snippet: string;
}

export interface ChangeOut {
  id: string;
  repo_target_id: string;
  repo_name: string;
  commit_sha: string;
  author_name: string;
  author_email: string;
  committed_at: string;
  message: string;
  origin: Origin;
  ai_tool: string;
  ai_model: string;
  prompt_ref: string;
  detection: string;
  lines_added: number;
  lines_removed: number;
  files_changed: number;
  files: string[];
  findings: GovFinding[];
  review_status: "none" | "approved" | "rejected";
  review_count: number;
  reviewed_by: string;
  reviewed_at: string | null;
  gate_status: GateStatus;
  gate_policy_name: string;
}

export interface ChangePage {
  total: number;
  items: ChangeOut[];
}

export interface GateViolation {
  code: string;
  message: string;
}

export interface GateResult {
  allowed: boolean;
  status: GateStatus;
  mode: string;
  policy: string;
  policy_id: string | null;
  violations: GateViolation[];
  change_id: string;
  commit_sha: string;
}

export interface GateRunOut {
  id: string;
  repo_target_id: string;
  repo_name: string;
  change_id: string;
  commit_sha: string;
  status: GateStatus;
  mode: string;
  policy_name: string;
  violations: GateViolation[];
  trigger: string;
  created_at: string;
}

export interface PolicyIn {
  name: string;
  repo_target_id: string | null;
  path_prefixes: string;
  ai_policy: "allowed" | "restricted" | "forbidden";
  required_reviews: number;
  block_on_severity: "none" | "critical" | "high" | "medium";
  mode: "observe" | "enforce";
  is_active: boolean;
}

export interface PolicyOut extends PolicyIn {
  id: string;
  repo_name: string;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface LedgerEntryOut {
  seq: number;
  ts: string;
  event_type: string;
  actor: string;
  subject: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
  signature: string;
}

export interface LedgerPage {
  total: number;
  items: LedgerEntryOut[];
}

export interface VerifyOut {
  ok: boolean;
  entries: number;
  head_hash: string;
  broken_at_seq: number | null;
  reason: string;
  anchor_checked: boolean;
}

export interface AnchorOut {
  entries: number;
  head_hash: string;
  generated_at: string;
  signature: string;
}

export interface Metrics {
  window_days: number;
  totals: {
    changes: number; human: number; ai: number; mixed: number; ai_changes: number;
    lines_added: number; ai_lines: number; human_lines: number; ai_share_pct: number; ai_lines_share_pct: number;
  };
  review: { ai_changes_needing_review: number; ai_changes_approved: number; coverage_pct: number; avg_review_hours: number | null };
  gate: { passed: number; blocked: number; observed_fail: number };
  findings: {
    in_ai_code: number; in_human_code: number; per_1000_lines_ai: number; per_1000_lines_human: number;
    severity_ai: Record<string, number>; severity_human: Record<string, number>;
  };
  roi: { hours_per_ai_change: number; estimated_hours_saved: number | null; note: string };
  tools: { tool: string; changes: number }[];
  by_repo: {
    repo_target_id: string; repo: string; changes: number; ai_changes: number; ai_share_pct: number;
    lines_added: number; ai_lines: number; findings: number; blocked: number;
  }[];
  weekly: { week: string; human_lines: number; ai_lines: number; findings: number; flagged: number }[];
  ledger: { entries: number; head_hash: string };
}

// --- Etiquetas (texto fuente en espanol: la UI lo traduce) ---------------------------------------

export const ORIGIN_LABEL: Record<string, string> = { human: "Humano", ai: "IA", mixed: "Mixto" };
export const GATE_LABEL: Record<string, string> = {
  passed: "Aprobado",
  blocked: "Bloqueado",
  observed_fail: "Hubiera bloqueado",
};
export const REVIEW_LABEL: Record<string, string> = { none: "Sin revisar", approved: "Aprobado", rejected: "Rechazado" };
export const AI_POLICY_LABEL: Record<string, string> = {
  allowed: "Permitida",
  restricted: "Permitida con revision",
  forbidden: "Prohibida",
};
export const MODE_LABEL: Record<string, string> = { observe: "Observar", enforce: "Exigir" };
export const SEVERITY_LABEL: Record<string, string> = {
  none: "Nunca",
  critical: "Critica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
};
export const TRIGGER_LABEL: Record<string, string> = {
  scan: "Escaneo",
  ci: "Pipeline (CI)",
  review: "Revision",
  manual: "Manual",
};
export const DETECTION_LABEL: Record<string, string> = {
  trailer: "Marca en el commit",
  declared: "Declarado por una persona",
  default: "Sin marcas (se asume humano)",
};
export const EVENT_LABEL: Record<string, string> = {
  "change.recorded": "Cambio registrado",
  "change.origin_declared": "Origen declarado",
  "change.reviewed": "Revision humana",
  "change.finding_added": "Hallazgo agregado",
  "gate.evaluated": "Compuerta evaluada",
  "policy.created": "Politica creada",
  "policy.updated": "Politica modificada",
  "policy.deleted": "Politica eliminada",
  "repo.connected": "Repositorio conectado",
  "repo.deleted": "Repositorio eliminado",
  "scan.ingested": "Escaneo de historial",
};

export const GATE_REASON_LABEL: Record<string, string> = {
  ai_forbidden: "IA no permitida en esta zona",
  findings_over_threshold: "Hallazgos por encima del umbral",
  missing_review: "Falta revision humana",
  review_rejected: "Rechazado en la revision",
};

// --- Helpers puros --------------------------------------------------------------------------------

export function shortSha(sha: string): string {
  return sha.length > 8 ? sha.slice(0, 8) : sha;
}

export function shortHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 12)}…` : hash;
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function severityCounts(findings: { severity: string }[]): Partial<Record<Severity, number>> {
  const out: Partial<Record<Severity, number>> = {};
  for (const f of findings) {
    const sev = (SEV_ORDER as string[]).includes(f.severity) ? (f.severity as Severity) : "low";
    out[sev] = (out[sev] ?? 0) + 1;
  }
  return out;
}

export function orderedSeverities(counts: Partial<Record<Severity, number>>): [Severity, number][] {
  return SEV_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => [s, counts[s] as number]);
}

export function formatPct(value: number): string {
  return `${Number.isInteger(value) ? value : value.toFixed(1)}%`;
}

export function isAiOrigin(origin: string): boolean {
  return origin === "ai" || origin === "mixed";
}

/** Barras apiladas por semana: porcentajes (0-100) de lineas humanas / IA, escaladas al maximo semanal. */
export function weeklyBars(
  weekly: { week: string; human_lines: number; ai_lines: number }[],
): { week: string; humanPct: number; aiPct: number; total: number }[] {
  const max = Math.max(1, ...weekly.map((w) => w.human_lines + w.ai_lines));
  return weekly.map((w) => ({
    week: w.week,
    total: w.human_lines + w.ai_lines,
    humanPct: Math.round((100 * w.human_lines) / max),
    aiPct: Math.round((100 * w.ai_lines) / max),
  }));
}

export type Translator = (key: string, ...args: (string | number)[]) => string;
const plain: Translator = (key, ...args) => key.replace(/\{(\d+)\}/g, (_m, n) => String(args[Number(n)] ?? ""));

/** Resumen corto y legible del detalle de una entrada del registro. */
export function summarizePayload(eventType: string, p: Record<string, unknown>, tr: Translator = plain): string {
  const s = (k: string) => (p[k] === undefined || p[k] === null ? "" : String(p[k]));
  const lbl = (m: Record<string, string>, v: string) => (v ? tr(m[v] ?? v) : v);
  switch (eventType) {
    case "change.recorded":
      return [s("repo"), s("origin") && tr("origen: {0}", lbl(ORIGIN_LABEL, s("origin"))), s("ai_tool"), s("gate") && tr("compuerta: {0}", lbl(GATE_LABEL, s("gate")))]
        .filter(Boolean).join(" · ");
    case "change.origin_declared": {
      const before = (p.before ?? {}) as Record<string, unknown>;
      const after = (p.after ?? {}) as Record<string, unknown>;
      return `${lbl(ORIGIN_LABEL, String(before.origin ?? "")) || "?"} → ${lbl(ORIGIN_LABEL, String(after.origin ?? "")) || "?"}${after.ai_tool ? ` (${after.ai_tool})` : ""}`;
    }
    case "change.reviewed":
      return `${s("decision") === "approve" ? tr("aprobo") : tr("rechazo")}${s("comment") ? `: ${s("comment")}` : ""}`;
    case "gate.evaluated":
      return `${lbl(GATE_LABEL, s("previous_status")) || "?"} → ${lbl(GATE_LABEL, s("status"))} · ${s("policy")} (${lbl(MODE_LABEL, s("mode"))})`;
    case "policy.created":
    case "policy.deleted":
      return `${s("name")} · ${lbl(MODE_LABEL, s("mode"))} · ${tr("IA {0}", lbl(AI_POLICY_LABEL, s("ai_policy")))}`;
    case "policy.updated": {
      const after = (p.after ?? {}) as Record<string, unknown>;
      return `${after.name ?? ""} · ${lbl(MODE_LABEL, String(after.mode ?? ""))} · ${tr("IA {0}", lbl(AI_POLICY_LABEL, String(after.ai_policy ?? "")))}`;
    }
    case "repo.connected":
    case "repo.deleted":
      return s("name") || s("repo_url");
    case "scan.ingested":
      return `${s("repo")}: ${tr("{0} nuevos, {1} con IA", s("new_changes"), s("ai_changes"))}`;
    default:
      return JSON.stringify(p).slice(0, 120);
  }
}

// --- Politicas: plantillas para empezar ---------------------------------------------------------

export const POLICY_TEMPLATES: { key: string; label: string; hint: string; value: Partial<PolicyIn> }[] = [
  {
    key: "observe",
    label: "Empezar observando",
    hint: "Mide todo y avisa, pero no bloquea nada. Ideal para el primer mes.",
    value: { name: "Base: observar todo", path_prefixes: "", ai_policy: "allowed", required_reviews: 0, block_on_severity: "high", mode: "observe" },
  },
  {
    key: "review",
    label: "IA con revision humana",
    hint: "El codigo con IA necesita al menos una aprobacion de otra persona.",
    value: { name: "IA con revision humana", path_prefixes: "", ai_policy: "restricted", required_reviews: 1, block_on_severity: "high", mode: "enforce" },
  },
  {
    key: "sensitive",
    label: "Zona sensible",
    hint: "Pagos, credenciales y seguridad: sin IA y sin hallazgos medios o mayores.",
    value: { name: "Zona sensible", path_prefixes: "src/pagos/, src/auth/, infra/", ai_policy: "forbidden", required_reviews: 2, block_on_severity: "medium", mode: "enforce" },
  },
];

export function policyScopeParts(p: Pick<PolicyIn, "path_prefixes" | "repo_target_id"> & { repo_name?: string }): { repo: string; zones: string } {
  const repo = p.repo_target_id ? p.repo_name || "un repositorio" : "Todos los repositorios";
  const zones = p.path_prefixes.split(/[,\n]/).map((x) => x.trim()).filter(Boolean).join(", ");
  return { repo, zones };
}

export function policyScope(p: Pick<PolicyIn, "path_prefixes" | "repo_target_id"> & { repo_name?: string }): string {
  const repo = p.repo_target_id ? p.repo_name || "un repositorio" : "Todos los repositorios";
  const zones = p.path_prefixes.split(/[,\n]/).map((x) => x.trim()).filter(Boolean);
  return zones.length ? `${repo} · ${zones.join(", ")}` : repo;
}

// --- Compuerta en el pipeline de CI -------------------------------------------------------------

export function buildCiWorkflow(apiBase: string, repoId: string): string {
  return `name: TERO gobernanza de codigo
on: [pull_request]
jobs:
  compuerta:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Consultar la compuerta de TERO
        env:
          TERO_URL: ${apiBase}
          TERO_TOKEN: \${{ secrets.TERO_TOKEN }}
        run: |
          SHA="\${{ github.event.pull_request.head.sha }}"
          BASE="origin/\${{ github.base_ref }}"
          jq -n \\
            --arg repo "${repoId}" --arg sha "$SHA" \\
            --arg msg "$(git log -1 --format=%B "$SHA")" \\
            --arg author "$(git log -1 --format=%ae "$SHA")" \\
            --arg diff "$(git diff -U0 "$BASE...$SHA" | head -c 900000)" \\
            --arg files "$(git diff --name-only "$BASE...$SHA")" \\
            '{repo_target_id:$repo, commit_sha:$sha, message:$msg, author_email:$author, diff:$diff,
              files:($files | split("\\n") | map(select(length > 0)))}' > body.json
          RESP=$(curl -sS -X POST "$TERO_URL/governance/gate/evaluate" \\
            -H "Authorization: Bearer $TERO_TOKEN" -H "Content-Type: application/json" -d @body.json)
          echo "$RESP" | jq .
          [ "$(echo "$RESP" | jq -r .allowed)" = "true" ] || { echo "TERO bloqueo este cambio"; exit 1; }
`;
}

export const COMMIT_TRAILER_EXAMPLE = `feat: agrega paginacion al listado

AI-Origin: mixed
AI-Tool: Cursor
AI-Model: gpt-5
AI-Prompt: agregar paginacion de 25 en 25 al listado de clientes`;
