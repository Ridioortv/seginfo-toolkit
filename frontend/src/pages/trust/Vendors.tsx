import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { caseApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { connectionErrorDetail } from "../../utils/errors";
import { saveBlob } from "../../utils/download";
import {
  ANSWER_LABEL, ASSESSMENT_STATUS_LABEL, CRITICALITY_HELP, CRITICALITY_LABEL, DATA_TYPE_LABEL, EVIDENCE_STATUS_BADGE,
  EVIDENCE_STATUS_LABEL, LEVEL_BADGE, LEVEL_LABEL, assessmentLink, dateToIso,
  type Criticality, type Vendor, type VendorAssessment, type VendorSummary,
} from "../../utils/vendors";
import { currentLocale, t } from "../../i18n";

const WRITERS = ["admin", "soc_manager"];

function when(ts: string | null | undefined, withTime = false): string {
  if (!ts) return "-";
  const d = new Date(ts);
  return withTime ? d.toLocaleString(currentLocale()) : d.toLocaleDateString(currentLocale());
}

interface VendorForm {
  name: string; domain: string; criticality: Criticality; service_description: string; data_types: string[];
  owner: string; contact_email: string; contract_end: string;
}
const EMPTY: VendorForm = {
  name: "", domain: "", criticality: "medium", service_description: "", data_types: [], owner: "", contact_email: "", contract_end: "",
};

interface EvidenceForm { kind: string; title: string; valid_until: string; reference_url: string; document_sha256: string }
const EMPTY_EVIDENCE: EvidenceForm = { kind: "iso27001", title: "", valid_until: "", reference_url: "", document_sha256: "" };
const EVIDENCE_KINDS: Record<string, string> = {
  iso27001: "ISO/IEC 27001", soc2: "SOC 2 tipo II", pentest: "Prueba de penetracion", dpa: "Contrato de proteccion de datos (DPA)",
  bcp: "Plan de continuidad", insurance: "Ciberseguro", other: "Otra",
};

function VendorFields({ form, setForm }: { form: VendorForm; setForm: (f: VendorForm) => void }) {
  const toggle = (k: string) =>
    setForm({ ...form, data_types: form.data_types.includes(k) ? form.data_types.filter((x) => x !== k) : [...form.data_types, k] });
  return (
    <div className="inline-form" style={{ flexWrap: "wrap", marginTop: 8 }}>
      <input type="text" placeholder={t("Nombre del proveedor")} maxLength={255} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
      <input type="text" placeholder={t("Dominio (ej. proveedor.com)")} maxLength={300} value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} />
      <select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value as Criticality })} aria-label={t("Criticidad")}>
        {(Object.keys(CRITICALITY_LABEL) as Criticality[]).map((k) => <option key={k} value={k}>{t("Criticidad")}: {t(CRITICALITY_LABEL[k])}</option>)}
      </select>
      <input type="text" placeholder={t("Responsable interno")} maxLength={255} value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
      <input type="email" placeholder={t("Email de contacto del proveedor")} maxLength={255} value={form.contact_email} onChange={(e) => setForm({ ...form, contact_email: e.target.value })} />
      <label className="empty-hint">{t("Fin del contrato")} <input type="date" value={form.contract_end} onChange={(e) => setForm({ ...form, contract_end: e.target.value })} /></label>
      <textarea rows={2} style={{ width: "100%" }} maxLength={2000} placeholder={t("Que servicio presta y para que lo usamos")} value={form.service_description}
        onChange={(e) => setForm({ ...form, service_description: e.target.value })} />
      <div style={{ width: "100%" }}>
        <span className="empty-hint">{t("Datos que maneja:")} </span>
        {Object.entries(DATA_TYPE_LABEL).map(([k, label]) => (
          <label key={k} className="gov-row-check" style={{ marginRight: 12 }}>
            <input type="checkbox" checked={form.data_types.includes(k)} onChange={() => toggle(k)} /> {t(label)}
          </label>
        ))}
      </div>
      <div className="empty-hint" style={{ width: "100%" }}>{t(CRITICALITY_HELP[form.criticality])}</div>
    </div>
  );
}

function formToBody(f: VendorForm) {
  return {
    name: f.name.trim(), domain: f.domain.trim(), criticality: f.criticality, service_description: f.service_description,
    data_types: f.data_types, owner: f.owner, contact_email: f.contact_email.trim(), contract_end: dateToIso(f.contract_end),
  };
}

function VendorDetail({ vendorId, canWrite, onClose }: { vendorId: string; canWrite: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<VendorForm>(EMPTY);
  const [days, setDays] = useState(30);
  const [link, setLink] = useState<{ url: string; expires: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [ev, setEv] = useState<EvidenceForm>(EMPTY_EVIDENCE);
  const [showEv, setShowEv] = useState(false);
  const [viewing, setViewing] = useState<VendorAssessment | null>(null);

  const q = useQuery({ queryKey: ["vendor", vendorId], queryFn: async () => (await caseApi.get<Vendor>(`/vendors/${vendorId}`)).data });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["vendor", vendorId] });
    queryClient.invalidateQueries({ queryKey: ["vendors"] });
    queryClient.invalidateQueries({ queryKey: ["vendors-summary"] });
  };
  const save = useMutation({
    mutationFn: async () => (await caseApi.patch(`/vendors/${vendorId}`, formToBody(form))).data,
    onSuccess: () => { setEditing(false); refresh(); },
  });
  const setStatus = useMutation({
    mutationFn: async (status: "active" | "offboarded") => (await caseApi.patch(`/vendors/${vendorId}`, { status })).data,
    onSuccess: refresh,
  });
  const send = useMutation({
    mutationFn: async () => (await caseApi.post<{ path: string; expires_at: string }>(`/vendors/${vendorId}/assessments`, { days })).data,
    onSuccess: (d) => { setLink({ url: assessmentLink(window.location.origin, d.path), expires: d.expires_at }); setCopied(false); refresh(); },
  });
  const cancel = useMutation({
    mutationFn: async (id: string) => (await caseApi.post(`/vendors/${vendorId}/assessments/${id}/cancel`)).data,
    onSuccess: refresh,
  });
  const detail = useMutation({
    mutationFn: async (id: string) => (await caseApi.get<VendorAssessment>(`/vendors/${vendorId}/assessments/${id}`)).data,
    onSuccess: setViewing,
  });
  const addEv = useMutation({
    mutationFn: async () => (await caseApi.post(`/vendors/${vendorId}/evidence`, {
      kind: ev.kind, title: ev.title.trim(), valid_until: dateToIso(ev.valid_until), reference_url: ev.reference_url.trim(),
      document_sha256: ev.document_sha256.trim().toLowerCase(),
    })).data,
    onSuccess: () => { setEv(EMPTY_EVIDENCE); setShowEv(false); refresh(); },
  });
  const delEv = useMutation({
    mutationFn: async (id: string) => (await caseApi.delete(`/vendors/${vendorId}/evidence/${id}`)).data,
    onSuccess: refresh,
  });

  const v = q.data;
  if (q.isLoading) return <div className="panel"><p className="empty-hint">Cargando...</p></div>;
  if (q.isError || !v) return <div className="panel"><p className="error-text"><span className="error-detail">{connectionErrorDetail(q.error)}</span></p></div>;

  const startEdit = () => {
    setForm({
      name: v.name, domain: v.domain, criticality: v.criticality, service_description: v.service_description, data_types: v.data_types,
      owner: v.owner, contact_email: v.contact_email, contract_end: v.contract_end ? v.contract_end.slice(0, 10) : "",
    });
    setEditing(true);
  };
  const copy = async () => {
    if (!link) return;
    try { await navigator.clipboard.writeText(link.url); setCopied(true); } catch { setCopied(false); }
  };
  const last = (v.assessments ?? []).find((a) => a.status === "completed");
  const domains = last?.score_detail.domains ?? {};

  return (
    <div className="panel">
      <div className="gov-row-actions" style={{ justifyContent: "space-between", marginTop: 0 }}>
        <h2 style={{ margin: 0 }}>{v.name} <span className={LEVEL_BADGE[v.risk.level]}>{t(LEVEL_LABEL[v.risk.level])}</span></h2>
        <button className="btn-link" onClick={onClose}>Cerrar ficha</button>
      </div>
      {v.status === "offboarded" && <div className="gov-callout gov-warn"><div>Este proveedor esta dado de baja. No se le pueden mandar cuestionarios.</div></div>}

      {!editing ? (
        <div style={{ marginTop: 8 }}>
          <div>{v.domain || "-"} · {t("Criticidad")}: <strong>{t(CRITICALITY_LABEL[v.criticality])}</strong> · {t("Responsable")}: {v.owner || "-"} · {t("Contacto")}: {v.contact_email || "-"}</div>
          <div className="empty-hint">{v.service_description || t("Sin descripcion del servicio.")}</div>
          <div className="empty-hint">{t("Datos que maneja:")} {v.data_types.length ? v.data_types.map((d) => t(DATA_TYPE_LABEL[d] ?? d)).join(", ") : "-"} · {t("Fin del contrato")}: {when(v.contract_end)}</div>
          {canWrite && (
            <div className="gov-row-actions">
              <button className="btn-secondary" onClick={startEdit}>Editar datos</button>
              {v.status === "active"
                ? <button className="btn-link" disabled={setStatus.isPending} onClick={() => { if (window.confirm(t("¿Dar de baja a este proveedor? Queda en el historial pero deja de contar en el riesgo."))) setStatus.mutate("offboarded"); }}>Dar de baja</button>
                : <button className="btn-link" disabled={setStatus.isPending} onClick={() => setStatus.mutate("active")}>Reactivar</button>}
            </div>
          )}
        </div>
      ) : (
        <div>
          <VendorFields form={form} setForm={setForm} />
          <div className="gov-row-actions">
            <button className="btn-primary" disabled={save.isPending || !form.name.trim()} onClick={() => save.mutate()}>Guardar cambios</button>
            <button className="btn-link" onClick={() => setEditing(false)}>Cancelar</button>
          </div>
          {save.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(save.error)}</span></p>}
        </div>
      )}
      {setStatus.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(setStatus.error)}</span></p>}

      <h3 style={{ marginTop: 18 }}>Riesgo</h3>
      {v.risk.index === null ? (
        <p className="empty-hint">Todavia no hay un cuestionario respondido: el riesgo no se puede calcular. Sin datos nunca se supone riesgo bajo.</p>
      ) : (
        <>
          <div className="cards-grid">
            <div className="stat-card"><span className="stat-label">Puntaje de controles</span><span className="stat-value">{v.risk.effective_score}</span><span className="empty-hint">{t("de 100 (incluye +{0} por evidencia vigente)", v.risk.evidence_bonus)}</span></div>
            <div className="stat-card"><span className="stat-label">Indice de riesgo</span><span className="stat-value">{v.risk.index}</span><span className="empty-hint">criticidad x lo que falta de controles</span></div>
            <div className="stat-card"><span className="stat-label">Ultima evaluacion</span><span className="stat-value" style={{ fontSize: "1.1rem" }}>{when(v.last_assessment_at)}</span>{v.risk.stale && <span className="empty-hint">Mas de 12 meses: hay que repetirla</span>}</div>
          </div>
          {Object.keys(domains).length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary>Puntaje por area</summary>
              <ul>{Object.entries(domains).map(([d, s]) => <li key={d}>{t(d)}: <strong>{s}</strong></li>)}</ul>
            </details>
          )}
          {(last?.score_detail.knockouts ?? []).length > 0 && (
            <div className="gov-callout gov-warn"><div>{t("Respondio \"No\" en {0} control(es) basico(s) (MFA, cifrado o aviso de brechas): resta puntos.", (last?.score_detail.knockouts ?? []).length)}</div></div>
          )}
        </>
      )}

      <h3 style={{ marginTop: 18 }}>Cuestionario de seguridad</h3>
      <p className="empty-hint">Se le manda al proveedor un link con vencimiento y un solo uso. Lo responde el, sin crear cuenta. Las respuestas quedan en la cadena de custodia.</p>
      {canWrite && v.status === "active" && (
        <div className="gov-row-actions">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label={t("Vigencia del link")}>
            <option value={7}>{t("El link vale 7 dias")}</option>
            <option value={30}>{t("El link vale 30 dias")}</option>
            <option value={60}>{t("El link vale 60 dias")}</option>
          </select>
          <button className="btn-primary" disabled={send.isPending} onClick={() => send.mutate()}>Generar link del cuestionario</button>
        </div>
      )}
      {send.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(send.error)}</span></p>}
      {link && (
        <div className="gov-callout">
          <div><strong>Link para el proveedor</strong> ({t("vale hasta el {0}", when(link.expires))}). Se muestra una sola vez: copialo y mandaselo.</div>
          <input type="text" readOnly value={link.url} style={{ width: "100%", marginTop: 6 }} onFocus={(e) => e.currentTarget.select()} aria-label={t("Link del cuestionario")} />
          <div className="gov-row-actions"><button className="btn-secondary" onClick={copy}>{copied ? t("Copiado") : t("Copiar link")}</button></div>
        </div>
      )}
      {(v.assessments ?? []).length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead><tr><th>Enviado</th><th>Estado</th><th>Respondio</th><th>Puntaje</th><th></th></tr></thead>
            <tbody>
              {(v.assessments ?? []).map((a) => (
                <tr key={a.id}>
                  <td>{when(a.created_at)}<div className="empty-hint">{a.created_by}</div></td>
                  <td>{t(ASSESSMENT_STATUS_LABEL[a.status] ?? a.status)}{a.status === "sent" && <div className="empty-hint">{t("vence el {0}", when(a.expires_at))}</div>}</td>
                  <td>{a.respondent_name ? `${a.respondent_name} (${a.respondent_email})` : "-"}<div className="empty-hint">{a.completed_at ? when(a.completed_at, true) : ""}</div></td>
                  <td>{a.score_base ?? "-"}</td>
                  <td>
                    <div className="gov-row-actions" style={{ marginTop: 0 }}>
                      {a.status === "completed" && <button className="btn-secondary" disabled={detail.isPending} onClick={() => detail.mutate(a.id)}>Ver respuestas</button>}
                      {canWrite && a.status === "sent" && <button className="btn-link" disabled={cancel.isPending} onClick={() => cancel.mutate(a.id)}>Cancelar</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(detail.isError || cancel.isError) && <p className="error-text"><span className="error-detail">{connectionErrorDetail(detail.error ?? cancel.error)}</span></p>}
      {viewing?.answers && (
        <details open style={{ marginTop: 8 }}>
          <summary>{t("Respuestas de {0}", viewing.respondent_name)}</summary>
          <table className="data-table">
            <thead><tr><th>Pregunta</th><th>Respuesta</th></tr></thead>
            <tbody>
              {viewing.answers.map((a) => (
                <tr key={a.id}>
                  <td>{t(a.text)}{a.knockout && <span className="badge badge-neutral" style={{ marginLeft: 6 }}>{t("control basico")}</span>}{a.comment && <div className="empty-hint">{a.comment}</div>}</td>
                  <td>{t(ANSWER_LABEL[a.answer] ?? a.answer)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}

      <h3 style={{ marginTop: 18 }}>Evidencia y certificaciones</h3>
      <p className="empty-hint">TERO guarda la ficha, el vencimiento y la huella del archivo; no valida el contenido del documento. La evidencia vigente suma hasta 10 puntos; la vencida no suma.</p>
      {(v.evidence ?? []).length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead><tr><th>Documento</th><th>Estado</th><th>Vence</th><th></th></tr></thead>
            <tbody>
              {(v.evidence ?? []).map((e) => (
                <tr key={e.id}>
                  <td>{t(e.kind_label)}: {e.title}{e.reference_url && <div className="empty-hint"><a href={e.reference_url} target="_blank" rel="noopener noreferrer">{t("Ver documento")}</a></div>}{e.document_sha256 && <div className="gov-hash">{e.document_sha256.slice(0, 16)}…</div>}</td>
                  <td><span className={EVIDENCE_STATUS_BADGE[e.status]}>{t(EVIDENCE_STATUS_LABEL[e.status])}</span></td>
                  <td>{e.valid_until ? when(e.valid_until) : t("Sin vencimiento")}</td>
                  <td>{canWrite && <button className="btn-link" disabled={delEv.isPending} onClick={() => delEv.mutate(e.id)}>Quitar</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {canWrite && !showEv && <div className="gov-row-actions"><button className="btn-secondary" onClick={() => setShowEv(true)}>Agregar evidencia</button></div>}
      {canWrite && showEv && (
        <div className="inline-form" style={{ flexWrap: "wrap", marginTop: 8 }}>
          <select value={ev.kind} onChange={(e) => setEv({ ...ev, kind: e.target.value })} aria-label={t("Tipo de evidencia")}>
            {Object.entries(EVIDENCE_KINDS).map(([k, label]) => <option key={k} value={k}>{t(label)}</option>)}
          </select>
          <input type="text" placeholder={t("Titulo (ej. Certificado ISO 27001 - 2026)")} maxLength={255} value={ev.title} onChange={(e) => setEv({ ...ev, title: e.target.value })} />
          <label className="empty-hint">{t("Vence")} <input type="date" value={ev.valid_until} onChange={(e) => setEv({ ...ev, valid_until: e.target.value })} /></label>
          <input type="url" placeholder={t("Link al documento (opcional)")} maxLength={500} value={ev.reference_url} onChange={(e) => setEv({ ...ev, reference_url: e.target.value })} />
          <input type="text" placeholder={t("Huella SHA-256 del archivo (opcional)")} maxLength={64} value={ev.document_sha256} onChange={(e) => setEv({ ...ev, document_sha256: e.target.value })} />
          <button className="btn-primary" disabled={addEv.isPending || ev.title.trim().length < 3} onClick={() => addEv.mutate()}>Guardar evidencia</button>
          <button className="btn-link" onClick={() => setShowEv(false)}>Cancelar</button>
        </div>
      )}
      {(addEv.isError || delEv.isError) && <p className="error-text"><span className="error-detail">{connectionErrorDetail(addEv.error ?? delEv.error)}</span></p>}
    </div>
  );
}

export default function Vendors() {
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const canWrite = WRITERS.includes(role);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState<VendorForm>(EMPTY);
  const [showOff, setShowOff] = useState(false);

  const summary = useQuery({ queryKey: ["vendors-summary"], queryFn: async () => (await caseApi.get<VendorSummary>("/vendors/summary")).data });
  const list = useQuery({
    queryKey: ["vendors", showOff],
    queryFn: async () => (await caseApi.get<Vendor[]>("/vendors", { params: { include_offboarded: showOff } })).data,
  });
  const create = useMutation({
    mutationFn: async () => (await caseApi.post<Vendor>("/vendors", formToBody(form))).data,
    onSuccess: (v) => {
      setCreating(false); setForm(EMPTY); setSelected(v.id);
      queryClient.invalidateQueries({ queryKey: ["vendors"] });
      queryClient.invalidateQueries({ queryKey: ["vendors-summary"] });
    },
  });
  const download = useMutation({
    mutationFn: async (kind: "csv" | "attestation") =>
      kind === "csv"
        ? saveBlob(await caseApi.get<Blob>("/vendors/report.csv", { responseType: "blob" }), "riesgo-proveedores.csv")
        : saveBlob(await caseApi.get<Blob>("/vendors/attestation", { responseType: "blob" }), "atestado-proveedores.json"),
  });

  const s = summary.data;
  return (
    <div>
      <div className="panel">
        <h2>Riesgo de proveedores</h2>
        <p className="empty-hint">
          Quienes tocan tus datos o sostienen tu operacion tambien son tu riesgo. Cargá a tus proveedores, mandales un
          cuestionario de seguridad por link, guardá sus certificaciones con vencimiento y mira cuales requieren seguimiento.
          El puntaje sale de las respuestas del propio proveedor: sirve para priorizar, no certifica a nadie.
        </p>
        {s && (
          <div className="cards-grid">
            <div className="stat-card"><span className="stat-label">Proveedores activos</span><span className="stat-value">{s.total}</span><span className="empty-hint">{t("{0} criticos para el negocio", s.critical_vendors)}</span></div>
            <div className="stat-card"><span className="stat-label">Riesgo alto o critico</span><span className="stat-value">{s.high_or_critical_risk}</span></div>
            <div className="stat-card"><span className="stat-label">Criticos sin evaluar</span><span className="stat-value">{s.without_assessment_critical_or_high}</span><span className="empty-hint">criticidad alta o critica, sin cuestionario vigente</span></div>
            <div className="stat-card"><span className="stat-label">Cuestionarios pendientes</span><span className="stat-value">{s.pending_questionnaires}</span></div>
            <div className="stat-card"><span className="stat-label">Evidencia vencida o por vencer</span><span className="stat-value">{s.expired_evidence + s.expiring_evidence}</span><span className="empty-hint">{t("{0} vencidas, {1} por vencer", s.expired_evidence, s.expiring_evidence)}</span></div>
            <div className="stat-card"><span className="stat-label">Contratos por vencer</span><span className="stat-value">{s.contracts_expiring}</span><span className="empty-hint">en los proximos 60 dias</span></div>
          </div>
        )}
        <div className="gov-row-actions">
          {canWrite && <button className="btn-primary" onClick={() => { setCreating(true); setSelected(null); }}>Nuevo proveedor</button>}
          <button className="btn-secondary" disabled={download.isPending} onClick={() => download.mutate("csv")}>Descargar listado (CSV)</button>
          <button className="btn-secondary" disabled={download.isPending || !canWrite} onClick={() => download.mutate("attestation")}>Descargar atestado firmado</button>
          <label className="gov-row-check"><input type="checkbox" checked={showOff} onChange={(e) => setShowOff(e.target.checked)} /> Mostrar proveedores dados de baja</label>
        </div>
        {download.isSuccess && <p className="empty-hint">{t("Listo: se descargo {0}.", download.data)}</p>}
        {download.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(download.error)}</span></p>}
        {creating && (
          <div style={{ marginTop: 12 }}>
            <strong>Nuevo proveedor</strong>
            <VendorFields form={form} setForm={setForm} />
            <div className="gov-row-actions">
              <button className="btn-primary" disabled={create.isPending || !form.name.trim()} onClick={() => create.mutate()}>Guardar proveedor</button>
              <button className="btn-link" onClick={() => setCreating(false)}>Cancelar</button>
            </div>
            {create.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(create.error)}</span></p>}
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Proveedores</h2>
        {list.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(list.error)}</span></p>}
        {list.isLoading && <p className="empty-hint">Cargando...</p>}
        {list.data && list.data.length === 0 && <p className="empty-hint">Todavia no cargaste proveedores. Empeza por los que manejan datos de clientes o sostienen tu operacion.</p>}
        {list.data && list.data.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead><tr><th>Proveedor</th><th>Criticidad</th><th>Riesgo</th><th>Ultima evaluacion</th><th>Evidencia</th><th></th></tr></thead>
              <tbody>
                {list.data.map((v) => (
                  <tr key={v.id}>
                    <td>{v.name}{v.status === "offboarded" && <span className="badge badge-neutral" style={{ marginLeft: 6 }}>{t("De baja")}</span>}<div className="empty-hint">{v.domain}</div></td>
                    <td>{t(CRITICALITY_LABEL[v.criticality])}</td>
                    <td>
                      <span className={LEVEL_BADGE[v.risk.level]}>{t(LEVEL_LABEL[v.risk.level])}</span>
                      {v.risk.index !== null && <span className="empty-hint"> {t("indice")} {v.risk.index}</span>}
                      {v.pending_assessment && <div className="empty-hint">{t("Cuestionario enviado, sin responder")}</div>}
                    </td>
                    <td>{when(v.last_assessment_at)}</td>
                    <td>
                      {v.evidence_counts.vigente + v.evidence_counts.por_vencer + v.evidence_counts.vencida === 0 ? "-" : (
                        <>
                          {v.evidence_counts.vigente > 0 && <span className="badge badge-success">{v.evidence_counts.vigente}</span>}{" "}
                          {v.evidence_counts.por_vencer > 0 && <span className="badge badge-medium">{v.evidence_counts.por_vencer}</span>}{" "}
                          {v.evidence_counts.vencida > 0 && <span className="badge badge-critical">{v.evidence_counts.vencida}</span>}
                        </>
                      )}
                    </td>
                    <td><button className="btn-secondary" onClick={() => { setSelected(v.id); setCreating(false); }}>Abrir ficha</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && <VendorDetail key={selected} vendorId={selected} canWrite={canWrite} onClose={() => setSelected(null)} />}
    </div>
  );
}
