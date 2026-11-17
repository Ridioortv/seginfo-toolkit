import { Fragment, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { caseApi, vulnApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { SeverityBadge } from "../../components/Badge";
import { connectionErrorDetail } from "../../utils/errors";
import { saveBlob } from "../../utils/download";
import {
  EXCEPTION_BADGE, EXCEPTION_LABEL, MIN_DAYS, canApprove, canDecide, maxDays,
  type ExceptionSummary, type RiskExceptionRow,
} from "../../utils/exceptions";
import { currentLocale, t } from "../../i18n";
import type { VulnerabilityOut } from "../../types";

function when(ts: string | null | undefined, withTime = false): string {
  if (!ts) return "-";
  const d = new Date(ts);
  return withTime ? d.toLocaleString(currentLocale()) : d.toLocaleDateString(currentLocale());
}

type Decision = { id: string; kind: "approve" | "reject" | "revoke" };

export default function Exceptions() {
  const queryClient = useQueryClient();
  const [params] = useSearchParams();
  const claims = useAuthStore((s) => s.claims);
  const role = claims?.role ?? "";
  const me = (claims?.email as string | undefined) ?? claims?.sub ?? "";
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(Boolean(params.get("vuln")));
  const [vulnId, setVulnId] = useState(params.get("vuln") ?? "");
  const [justification, setJustification] = useState("");
  const [controls, setControls] = useState("");
  const [days, setDays] = useState(60);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [note, setNote] = useState("");

  const summary = useQuery({ queryKey: ["exc-summary"], queryFn: async () => (await caseApi.get<ExceptionSummary>("/risk-exceptions/summary")).data, refetchInterval: 60_000 });
  const list = useQuery({
    queryKey: ["exc-list", filter], refetchInterval: 60_000,
    queryFn: async () => (await caseApi.get<RiskExceptionRow[]>("/risk-exceptions", { params: filter ? { status: filter } : {} })).data,
  });
  const vulns = useQuery({
    queryKey: ["exc-vulns"], enabled: creating,
    queryFn: async () => (await vulnApi.get<VulnerabilityOut[]>("/vulnerabilities", { params: { limit: 500 } })).data,
  });
  const preselected = useQuery({
    queryKey: ["exc-vuln", vulnId], enabled: creating && Boolean(vulnId) && !(vulns.data ?? []).some((v) => v.id === vulnId),
    queryFn: async () => (await vulnApi.get<VulnerabilityOut>(`/vulnerabilities/${vulnId}`)).data,
  });
  useEffect(() => { if (params.get("vuln")) setCreating(true); }, [params]);

  const candidates = (vulns.data ?? []).filter((v) => v.status === "open" || v.status === "confirmed");
  const picked = candidates.find((v) => v.id === vulnId) ?? (preselected.data && preselected.data.id === vulnId ? preselected.data : undefined);
  const severity = picked?.severity ?? "high";
  const limit = maxDays(severity);
  const strict = severity === "critical" || severity === "high";

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["exc-list"] });
    queryClient.invalidateQueries({ queryKey: ["exc-summary"] });
    queryClient.invalidateQueries({ queryKey: ["vulns"] });
  };
  const create = useMutation({
    mutationFn: async () => (await caseApi.post("/risk-exceptions", { vuln_id: vulnId, justification, compensating_controls: controls, days })).data,
    onSuccess: () => { setCreating(false); setVulnId(""); setJustification(""); setControls(""); setDays(60); refresh(); },
  });
  const decide = useMutation({
    mutationFn: async (d: Decision) => (await caseApi.post(`/risk-exceptions/${d.id}/${d.kind}`, { note })).data,
    onSuccess: () => { setDecision(null); setNote(""); refresh(); },
  });
  const withdraw = useMutation({ mutationFn: async (id: string) => (await caseApi.post(`/risk-exceptions/${id}/withdraw`)).data, onSuccess: refresh });
  const download = useMutation({
    mutationFn: async (id: string | "csv") =>
      id === "csv"
        ? saveBlob(await caseApi.get<Blob>("/risk-exceptions/register.csv", { responseType: "blob" }), "registro-excepciones-de-riesgo.csv")
        : saveBlob(await caseApi.get<Blob>(`/risk-exceptions/${id}/attestation`, { responseType: "blob" }), "prueba-excepcion.json"),
  });

  const s = summary.data;
  const formOk = Boolean(vulnId) && justification.trim().length >= 30 && (!strict || controls.trim().length >= 20) && days >= MIN_DAYS && days <= limit;

  return (
    <div>
      <div className="panel">
        <h2>Excepciones de riesgo</h2>
        <p className="empty-hint">
          Dejar abierta una vulnerabilidad alta o critica es una decision de negocio, y tiene que quedar firmada: quien la pide
          explica por que y con que controles se compensa, otra persona la aprueba, y vence sola. Al vencer, la vulnerabilidad
          vuelve a abrirse. Todo queda en la cadena de custodia y se puede bajar una prueba firmada de cada excepcion.
        </p>
        {s && (
          <div className="cards-grid">
            <div className="stat-card"><span className="stat-label">Pendientes de aprobar</span><span className="stat-value">{s.pending}</span></div>
            <div className="stat-card"><span className="stat-label">Vigentes</span><span className="stat-value">{s.active}</span><span className="empty-hint">{t("{0} altas o criticas", s.active_critical_or_high)}</span></div>
            <div className="stat-card"><span className="stat-label">Por vencer</span><span className="stat-value">{s.expiring_soon}</span><span className="empty-hint">en los proximos 14 dias</span></div>
            <div className="stat-card"><span className="stat-label">Vencidas (30 dias)</span><span className="stat-value">{s.expired_last_30_days}</span></div>
            <div className="stat-card"><span className="stat-label">Rechazadas (30 dias)</span><span className="stat-value">{s.rejected_last_30_days}</span></div>
          </div>
        )}
        {s?.self_approval_allowed && <div className="gov-callout gov-warn"><div>Esta instalacion permite que una persona apruebe sus propios pedidos (RISK_EXCEPTION_ALLOW_SELF_APPROVAL). Queda anotado en la cadena de custodia.</div></div>}
        <div className="gov-row-actions">
          <button className="btn-primary" onClick={() => setCreating(true)}>Pedir una excepcion</button>
          <button className="btn-secondary" disabled={download.isPending} onClick={() => download.mutate("csv")}>Descargar registro (CSV)</button>
          <select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label={t("Filtrar por estado")}>
            <option value="">{t("Todos los estados")}</option>
            {Object.entries(EXCEPTION_LABEL).map(([k, label]) => <option key={k} value={k}>{t(label)}</option>)}
          </select>
        </div>
        {download.isSuccess && <p className="empty-hint">{t("Listo: se descargo {0}.", download.data)}</p>}
        {download.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(download.error)}</span></p>}

        {creating && (
          <div style={{ marginTop: 12 }}>
            <strong>Nueva excepcion</strong>
            <div className="inline-form" style={{ flexWrap: "wrap", marginTop: 8 }}>
              <select value={vulnId} onChange={(e) => setVulnId(e.target.value)} aria-label={t("Vulnerabilidad")} style={{ width: "100%" }}>
                <option value="">{vulns.isLoading ? t("Cargando...") : t("Elegi la vulnerabilidad")}</option>
                {preselected.data && !candidates.some((v) => v.id === preselected.data!.id) && (
                  <option value={preselected.data.id}>[{preselected.data.severity}] {preselected.data.title}</option>
                )}
                {candidates.map((v) => <option key={v.id} value={v.id}>[{v.severity}] {v.title}{v.cve_id ? ` (${v.cve_id})` : ""}</option>)}
              </select>
              <textarea rows={3} style={{ width: "100%" }} maxLength={3000} value={justification} onChange={(e) => setJustification(e.target.value)}
                placeholder={t("Por que no se puede corregir ahora (minimo 30 letras)")} />
              <textarea rows={3} style={{ width: "100%" }} maxLength={3000} value={controls} onChange={(e) => setControls(e.target.value)}
                placeholder={strict ? t("Controles compensatorios: que reduce el riesgo mientras tanto (obligatorio, minimo 20 letras)") : t("Controles compensatorios (opcional)")} />
              <label className="empty-hint">
                {t("Dias de excepcion")} <input type="number" min={MIN_DAYS} max={limit} value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ width: 90 }} />
                {" "}{t("(entre {0} y {1} para una vulnerabilidad {2})", MIN_DAYS, limit, picked ? picked.severity : "-")}
              </label>
            </div>
            <div className="gov-row-actions">
              <button className="btn-primary" disabled={create.isPending || !formOk} onClick={() => create.mutate()}>Enviar a aprobacion</button>
              <button className="btn-link" onClick={() => setCreating(false)}>Cancelar</button>
            </div>
            {create.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(create.error)}</span></p>}
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Registro de excepciones</h2>
        {list.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(list.error)}</span></p>}
        {list.isLoading && <p className="empty-hint">Cargando...</p>}
        {list.data && list.data.length === 0 && <p className="empty-hint">No hay excepciones todavia. Se piden desde aca o desde el detalle de una vulnerabilidad alta o critica.</p>}
        {(decide.isError || withdraw.isError) && <p className="error-text"><span className="error-detail">{connectionErrorDetail(decide.error ?? withdraw.error)}</span></p>}
        {list.data && list.data.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead><tr><th>Vulnerabilidad</th><th>Severidad</th><th>Estado</th><th>Pidio</th><th>Vence</th><th></th></tr></thead>
              <tbody>
                {list.data.map((r) => (
                  <Fragment key={r.id}>
                    <tr>
                      <td>{r.vuln_title}{r.cve_id && <div className="gov-hash">{r.cve_id}</div>}</td>
                      <td><SeverityBadge value={r.severity} /></td>
                      <td>
                        <span className={EXCEPTION_BADGE[r.status]}>{t(EXCEPTION_LABEL[r.status])}</span>
                        {r.expiring_soon && <div className="empty-hint">{t("vence en {0} dias", r.days_left ?? 0)}</div>}
                        {r.end_reason && r.status !== "pending" && r.status !== "approved" && <div className="empty-hint">{r.end_reason}</div>}
                      </td>
                      <td>{r.requested_by}<div className="empty-hint">{when(r.requested_at)}</div></td>
                      <td>{r.expires_at ? when(r.expires_at) : r.status === "pending" ? t("{0} dias si se aprueba", r.requested_days) : "-"}{r.decided_by && <div className="empty-hint">{t("decidio {0}", r.decided_by)}</div>}</td>
                      <td>
                        <div className="gov-row-actions" style={{ marginTop: 0 }}>
                          <button className="btn-link" onClick={() => setOpen(open === r.id ? null : r.id)}>{open === r.id ? t("Ocultar detalle") : t("Ver detalle")}</button>
                          {canApprove(r, me, role, Boolean(s?.self_approval_allowed)) && (
                            <>
                              <button className="btn-secondary" onClick={() => { setDecision({ id: r.id, kind: "approve" }); setNote(""); }}>Aprobar</button>
                              <button className="btn-secondary" onClick={() => { setDecision({ id: r.id, kind: "reject" }); setNote(""); }}>Rechazar</button>
                            </>
                          )}
                          {r.status === "pending" && r.requested_by.toLowerCase() === me.toLowerCase() && (
                            <button className="btn-link" disabled={withdraw.isPending} onClick={() => withdraw.mutate(r.id)}>Retirar pedido</button>
                          )}
                          {r.status === "approved" && canDecide(role, r.severity) && (
                            <button className="btn-link" onClick={() => { setDecision({ id: r.id, kind: "revoke" }); setNote(""); }}>Revocar</button>
                          )}
                          {r.status !== "pending" && <button className="btn-link" disabled={download.isPending} onClick={() => download.mutate(r.id)}>Descargar prueba</button>}
                        </div>
                        {r.status === "pending" && r.requested_by.toLowerCase() === me.toLowerCase() && !s?.self_approval_allowed && (role === "admin" || role === "soc_manager") && (
                          <div className="empty-hint">{t("La tiene que aprobar otra persona.")}</div>
                        )}
                        {r.status === "pending" && r.severity === "critical" && role === "soc_manager" && <div className="empty-hint">{t("Una critica la aprueba un administrador.")}</div>}
                      </td>
                    </tr>
                    {decision?.id === r.id && (
                      <tr><td colSpan={6}>
                        <div className="inline-form" style={{ flexWrap: "wrap" }}>
                          <textarea rows={2} style={{ width: "100%" }} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)}
                            placeholder={decision.kind === "approve" ? t("Por que se aprueba (minimo 10 letras)") : decision.kind === "reject" ? t("Por que se rechaza (minimo 10 letras)") : t("Por que se revoca (minimo 10 letras)")} />
                          <button className="btn-primary" disabled={decide.isPending || note.trim().length < 10} onClick={() => decide.mutate(decision)}>
                            {decision.kind === "approve" ? t("Confirmar aprobacion") : decision.kind === "reject" ? t("Confirmar rechazo") : t("Confirmar revocacion")}
                          </button>
                          <button className="btn-link" onClick={() => setDecision(null)}>Cancelar</button>
                        </div>
                      </td></tr>
                    )}
                    {open === r.id && (
                      <tr><td colSpan={6}>
                        <div className="gov-callout">
                          <div><strong>Justificacion</strong><br />{r.justification}</div>
                          <div style={{ marginTop: 8 }}><strong>Controles compensatorios</strong><br />{r.compensating_controls || "-"}</div>
                          {r.decision_note && <div style={{ marginTop: 8 }}><strong>{t("Decision de {0} ({1})", r.decided_by, when(r.decided_at, true))}</strong><br />{r.decision_note}</div>}
                          <div className="empty-hint" style={{ marginTop: 8 }}>{t("Pedida el {0} por {1} por {2} dias.", when(r.requested_at, true), r.requested_by, r.requested_days)}</div>
                        </div>
                      </td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
