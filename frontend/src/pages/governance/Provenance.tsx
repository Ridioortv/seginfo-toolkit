import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { coderepoApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { SeverityBadge } from "../../components/Badge";
import { connectionErrorDetail } from "../../utils/errors";
import {
  COMMIT_TRAILER_EXAMPLE, DETECTION_LABEL, GATE_LABEL, GATE_REASON_LABEL, ORIGIN_LABEL, REVIEW_LABEL,
  isAiOrigin, orderedSeverities, severityCounts, shortSha,
  type ChangeOut, type ChangePage, type GateResult, type Origin,
} from "../../utils/governance";
import { currentLocale, t } from "../../i18n";
import type { RepoTargetOut } from "../../types";

const PAGE_SIZE = 25;
const WRITERS = ["admin", "soc_manager", "analyst"];

export function GateBadge({ value }: { value: string }) {
  const cls = value === "passed" ? "badge badge-success" : value === "blocked" ? "badge badge-critical" : "badge badge-medium";
  return <span className={cls}>{GATE_LABEL[value] ?? value}</span>;
}

function OriginBadge({ c }: { c: ChangeOut }) {
  const cls = c.origin === "human" ? "badge badge-neutral" : c.origin === "ai" ? "badge badge-high" : "badge badge-medium";
  return (
    <>
      <span className={cls}>{ORIGIN_LABEL[c.origin] ?? c.origin}</span>
      {isAiOrigin(c.origin) && (c.ai_tool || c.ai_model) && (
        <div className="empty-hint" style={{ margin: "4px 0 0" }}>{[c.ai_tool, c.ai_model].filter(Boolean).join(" · ")}</div>
      )}
    </>
  );
}

function ChangeDetail({ c, canWrite, email }: { c: ChangeOut; canWrite: boolean; email: string }) {
  const queryClient = useQueryClient();
  const [comment, setComment] = useState("");
  const [origin, setOrigin] = useState<Origin>(c.origin);
  const [tool, setTool] = useState(c.ai_tool);
  const [model, setModel] = useState(c.ai_model);
  const [prompt, setPrompt] = useState(c.prompt_ref);
  const [result, setResult] = useState<GateResult | null>(null);
  const [error, setError] = useState<unknown>(null);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["gov-changes"] });
    queryClient.invalidateQueries({ queryKey: ["gov-metrics"] });
    queryClient.invalidateQueries({ queryKey: ["gov-ledger"] });
    queryClient.invalidateQueries({ queryKey: ["gov-runs"] });
  };
  const review = useMutation({
    mutationFn: async (decision: "approve" | "reject") =>
      (await coderepoApi.post<GateResult>(`/governance/changes/${c.id}/review`, { decision, comment })).data,
    onSuccess: (r) => { setResult(r); setError(null); setComment(""); refresh(); },
    onError: (e: unknown) => setError(e),
  });
  const declare = useMutation({
    mutationFn: async () =>
      (await coderepoApi.patch<GateResult>(`/governance/changes/${c.id}`, {
        origin, ai_tool: tool, ai_model: model, prompt_ref: prompt,
      })).data,
    onSuccess: (r) => { setResult(r); setError(null); refresh(); },
    onError: (e: unknown) => setError(e),
  });

  const isAuthor = !!email && email.toLowerCase() === c.author_email.toLowerCase();

  return (
    <div className="gov-detail">
      <h4>Como se detecto el origen</h4>
      <div>{DETECTION_LABEL[c.detection] ?? c.detection}</div>
      {c.prompt_ref && (<><h4>Prompt declarado</h4><div>{c.prompt_ref}</div></>)}

      <h4>{t("Archivos ({0})", c.files_changed)}</h4>
      {c.files.length === 0 ? <div className="empty-hint">Sin archivos registrados.</div> : (
        <code className="gov-code">{c.files.slice(0, 40).join("\n")}{c.files.length > 40 ? "\n…" : ""}</code>
      )}

      <h4>{t("Hallazgos ({0})", c.findings.length)}</h4>
      {c.findings.length === 0 ? <div className="empty-hint">Ningun patron inseguro ni secreto en este cambio.</div> : (
        <table className="data-table">
          <thead><tr><th>Severidad</th><th>Regla</th><th>Ubicacion</th><th>Origen</th></tr></thead>
          <tbody>
            {c.findings.map((f, i) => (
              <tr key={i}>
                <td><SeverityBadge value={f.severity} /></td>
                <td>{f.description || f.rule_id}</td>
                <td className="mono">{f.file}{f.line != null ? `:${f.line}` : ""}</td>
                <td>{f.source === "gitleaks" ? "Secretos (gitleaks)" : f.source === "ci" ? "Pipeline" : "Patrones de codigo"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {canWrite && (
        <>
          <h4>Revision humana</h4>
          <div className="inline-form">
            <input placeholder="Comentario (opcional)" value={comment} onChange={(e) => setComment(e.target.value)} />
            <button className="btn-primary" disabled={review.isPending} onClick={() => review.mutate("approve")}>Aprobar</button>
            <button className="btn-secondary" disabled={review.isPending} onClick={() => review.mutate("reject")}>Rechazar</button>
          </div>
          {isAuthor && <p className="empty-hint">Sos quien escribio este cambio: donde la politica es de modo "Exigir", lo tiene que aprobar otra persona.</p>}

          <h4>Declarar o corregir el origen</h4>
          <div className="gov-form-grid">
            <div>
              <label>Origen</label>
              <select value={origin} onChange={(e) => setOrigin(e.target.value as Origin)}>
                <option value="human">Humano</option>
                <option value="mixed">Mixto (persona + IA)</option>
                <option value="ai">IA</option>
              </select>
            </div>
            <div><label>Herramienta</label><input value={tool} onChange={(e) => setTool(e.target.value)} placeholder="Cursor, Claude, Copilot..." disabled={origin === "human"} /></div>
            <div><label>Modelo</label><input value={model} onChange={(e) => setModel(e.target.value)} disabled={origin === "human"} /></div>
            <div><label>Prompt (resumen)</label><input value={prompt} onChange={(e) => setPrompt(e.target.value)} disabled={origin === "human"} /></div>
          </div>
          <button className="btn-secondary" disabled={declare.isPending} onClick={() => declare.mutate()}>Guardar declaracion</button>
          <span className="empty-hint"> Queda en el registro auditable con el valor anterior y el nuevo.</span>
        </>
      )}

      {result && (
        <div className={`gov-callout ${result.status === "passed" ? "gov-ok" : result.status === "blocked" ? "gov-bad" : "gov-warn"}`} style={{ marginTop: 12 }}>
          <strong>Compuerta: {GATE_LABEL[result.status] ?? result.status}</strong> (politica "{result.policy}", modo {result.mode})
          {result.violations.map((v) => (<div key={v.code}>{GATE_REASON_LABEL[v.code] ?? v.code}: {v.message}</div>))}
        </div>
      )}
      {error != null && <p className="error-text"><span className="error-detail">{connectionErrorDetail(error)}</span></p>}
    </div>
  );
}

export default function Provenance() {
  const claims = useAuthStore((s) => s.claims);
  const canWrite = !!claims?.role && WRITERS.includes(claims.role);
  const email = (claims as { email?: string } | null)?.email ?? "";
  const [repo, setRepo] = useState("");
  const [origin, setOrigin] = useState("");
  const [gate, setGate] = useState("");
  const [page, setPage] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const [showTrailers, setShowTrailers] = useState(false);

  const repos = useQuery({
    queryKey: ["code-repos"],
    queryFn: async () => (await coderepoApi.get<RepoTargetOut[]>("/repos")).data,
  });
  const changes = useQuery({
    queryKey: ["gov-changes", repo, origin, gate, page],
    queryFn: async () =>
      (await coderepoApi.get<ChangePage>("/governance/changes", {
        params: {
          ...(repo ? { repo_target_id: repo } : {}), ...(origin ? { origin } : {}), ...(gate ? { gate_status: gate } : {}),
          limit: PAGE_SIZE, offset: page * PAGE_SIZE,
        },
      })).data,
  });

  const total = changes.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const reset = (fn: (v: string) => void) => (e: React.ChangeEvent<HTMLSelectElement>) => { fn(e.target.value); setPage(0); setOpen(null); };

  return (
    <div>
      <div className="panel">
        <h2>Quien escribio cada cambio</h2>
        <p className="empty-hint">
          Cada commit de tus repositorios queda registrado con su autor, si lo escribio una persona, una IA o ambas, la
          herramienta y el modelo, cuantas lineas toco y que hallazgos tiene. Es el contador de modificaciones de codigo.
        </p>
        <div className="inline-form">
          <select value={repo} onChange={reset(setRepo)}>
            <option value="">Todos los repositorios</option>
            {(repos.data ?? []).map((r) => (<option key={r.id} value={r.id}>{r.name}</option>))}
          </select>
          <select value={origin} onChange={reset(setOrigin)}>
            <option value="">Cualquier origen</option>
            <option value="human">Humano</option>
            <option value="mixed">Mixto</option>
            <option value="ai">IA</option>
          </select>
          <select value={gate} onChange={reset(setGate)}>
            <option value="">Cualquier resultado de la compuerta</option>
            <option value="passed">Aprobado</option>
            <option value="blocked">Bloqueado</option>
            <option value="observed_fail">Hubiera bloqueado</option>
          </select>
        </div>
        <p className="empty-hint" style={{ marginBottom: 0 }}>
          <button className="btn-link" onClick={() => setShowTrailers((v) => !v)}>
            {showTrailers ? "Ocultar" : "Como marcar un commit para que la deteccion sea exacta"}
          </button>
        </p>
        {showTrailers && (
          <>
            <p className="empty-hint">
              TERO reconoce solo las marcas que dejan Claude, Copilot, Cursor, Aider y otras (lineas Co-Authored-By).
              Para marcar a mano, agrega estas lineas al final del mensaje del commit:
            </p>
            <code className="gov-code">{COMMIT_TRAILER_EXAMPLE}</code>
          </>
        )}
      </div>

      <div className="panel">
        {changes.isLoading && <p className="empty-hint">Cargando...</p>}
        {changes.isError && (
          <p className="error-text">No se pudo cargar. <span className="error-detail">{connectionErrorDetail(changes.error)}</span></p>
        )}
        {changes.data && changes.data.items.length === 0 && (
          <p className="empty-hint">Todavia no hay cambios registrados. Escanea un repositorio en "Código y Repositorios" para llenar el contador.</p>
        )}
        {changes.data && changes.data.items.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Fecha</th><th>Repositorio</th><th>Commit</th><th>Autor</th><th>Origen</th>
                <th>Lineas</th><th>Hallazgos</th><th>Revision</th><th>Compuerta</th><th></th>
              </tr>
            </thead>
            <tbody>
              {changes.data.items.map((c) => (
                <Fragment key={c.id}>
                  <tr>
                    <td>{new Date(c.committed_at).toLocaleDateString(currentLocale())}</td>
                    <td>{c.repo_name}</td>
                    <td><span className="mono">{shortSha(c.commit_sha)}</span><div className="empty-hint" style={{ margin: "2px 0 0" }}>{c.message}</div></td>
                    <td>{c.author_name || c.author_email}</td>
                    <td><OriginBadge c={c} /></td>
                    <td><span style={{ color: "var(--success)" }}>+{c.lines_added}</span> <span style={{ color: "var(--danger)" }}>-{c.lines_removed}</span></td>
                    <td>
                      {orderedSeverities(severityCounts(c.findings)).map(([sev, n]) => (
                        <span key={sev} style={{ marginRight: 4 }}><SeverityBadge value={sev} /> {n}</span>
                      ))}
                      {c.findings.length === 0 && "—"}
                    </td>
                    <td>{REVIEW_LABEL[c.review_status] ?? c.review_status}{c.review_count > 0 ? ` (${c.review_count})` : ""}</td>
                    <td><GateBadge value={c.gate_status} /></td>
                    <td><button className="btn-link" onClick={() => setOpen(open === c.id ? null : c.id)}>{open === c.id ? "Cerrar" : "Detalle"}</button></td>
                  </tr>
                  {open === c.id && (<tr><td colSpan={10}><ChangeDetail c={c} canWrite={canWrite} email={email} /></td></tr>)}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
        {total > PAGE_SIZE && (
          <div className="gov-pager">
            <span>{t("{0} cambios", total)}</span>
            <button className="btn-secondary" disabled={page === 0} onClick={() => { setPage(page - 1); setOpen(null); }}>Anterior</button>
            <span>{t("Pagina {0} de {1}", page + 1, pages)}</span>
            <button className="btn-secondary" disabled={page + 1 >= pages} onClick={() => { setPage(page + 1); setOpen(null); }}>Siguiente</button>
          </div>
        )}
      </div>
    </div>
  );
}
