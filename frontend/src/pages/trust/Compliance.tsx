import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { caseApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { connectionErrorDetail } from "../../utils/errors";
import { saveBlob } from "../../utils/download";
import {
  ANSWER_BADGE, ANSWER_LABEL, BASIS_LABEL, CONTROL_STATUS_BADGE, CONTROL_STATUS_LABEL, canDeclare, needsAction, sparkPoints,
  type ComplianceControl, type ComplianceStatus, type Msg,
} from "../../utils/trust";
import { currentLocale, t } from "../../i18n";

const WRITERS = ["admin", "soc_manager"];
const ISO = /^\d{4}-\d{2}-\d{2}T/;

function when(ts: string | null | undefined): string {
  return ts ? new Date(ts).toLocaleString(currentLocale()) : "-";
}

function msg(m: Msg): string {
  return t(m.text, ...m.args);
}

function observed(value: string): string {
  return ISO.test(value) ? when(value) : t(value);
}

interface Form { answer: "yes" | "partial" | "no"; note: string; months: number }
const EMPTY: Form = { answer: "yes", note: "", months: 12 };

export default function Compliance() {
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const canWrite = WRITERS.includes(role);
  const [onlyOpen, setOnlyOpen] = useState(false);
  const [declaring, setDeclaring] = useState<string | null>(null);
  const [form, setForm] = useState<Form>(EMPTY);

  const status = useQuery({
    queryKey: ["compliance-status"],
    queryFn: async () => (await caseApi.get<ComplianceStatus>("/compliance/status")).data,
    refetchInterval: 60_000,
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["compliance-status"] });

  const snapshot = useMutation({ mutationFn: async () => (await caseApi.post("/compliance/snapshot")).data, onSuccess: refresh });
  const declare = useMutation({
    mutationFn: async (controlId: string) =>
      (await caseApi.post("/compliance/declarations", { control_id: controlId, answer: form.answer, note: form.note, valid_months: form.months })).data,
    onSuccess: () => { setDeclaring(null); setForm(EMPTY); refresh(); },
  });
  const undeclare = useMutation({
    mutationFn: async (controlId: string) => (await caseApi.delete(`/compliance/declarations/${controlId}`)).data,
    onSuccess: refresh,
  });
  const download = useMutation({
    mutationFn: async (kind: "attestation" | "csv") =>
      kind === "attestation"
        ? saveBlob(await caseApi.get<Blob>("/compliance/attestation", { responseType: "blob" }), "atestado-cumplimiento.json")
        : saveBlob(await caseApi.get<Blob>("/compliance/questionnaire.csv", { responseType: "blob" }), "cuestionario-ciberseguro.csv"),
    onSuccess: refresh,
  });

  const s = status.data;
  const controls = (s?.controls ?? []).filter((c) => !onlyOpen || needsAction(c));
  const areas = [...new Set(controls.map((c) => c.area))];
  const sum = s?.summary;
  const done = sum ? (sum.counts.cumple ?? 0) + (sum.counts.declarado_si ?? 0) : 0;
  const toDeclare = sum ? (sum.counts.pendiente ?? 0) + (sum.counts.vencido ?? 0) : 0;
  const history = s?.history ?? [];

  const startDeclare = (c: ComplianceControl) => {
    setDeclaring(c.id);
    setForm(c.declaration ? { answer: c.declaration.answer, note: c.declaration.note, months: 12 } : EMPTY);
  };

  return (
    <div>
      <div className="panel">
        <h2>Cumplimiento con evidencia viva</h2>
        <p className="empty-hint">
          Ley 25.326 de Proteccion de los Datos Personales, medidas recomendadas por la Res. AAIP 47/2018 y los puntos que
          pide un seguro de ciberseguridad. Cada control se comprueba con datos reales de TERO (usuarios con MFA, escaneos,
          vulnerabilidades abiertas...) y lo que TERO no puede ver lo declara una persona, con nota, fecha y vencimiento.
          Lo verificado y lo declarado nunca se mezclan sin decirlo.
        </p>
        {s && <div className="gov-callout gov-warn"><div>{t(s.disclaimer)}</div></div>}
        {status.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(status.error)}</span></p>}
        {status.isLoading && <p className="empty-hint">Cargando...</p>}
        {sum && (
          <>
            <div className="cards-grid">
              <div className="stat-card">
                <span className="stat-label">Verificado por TERO</span>
                <span className="stat-value">{sum.score_verified === null ? "-" : `${sum.score_verified}%`}</span>
                <span className="empty-hint">{t("{0} de {1} controles comprobados con datos reales", sum.verified_controls, sum.automatic_controls)}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Con lo declarado</span>
                <span className="stat-value">{sum.score_total === null ? "-" : `${sum.score_total}%`}</span>
                <span className="empty-hint">{t("sobre {0} controles; lo pendiente cuenta como no cumplido", sum.total_controls)}</span>
              </div>
              <div className="stat-card"><span className="stat-label">Controles al dia</span><span className="stat-value">{done}</span></div>
              <div className="stat-card"><span className="stat-label">Para resolver</span><span className="stat-value">{sum.total_controls - done}</span></div>
              <div className="stat-card"><span className="stat-label">Sin declarar o vencidos</span><span className="stat-value">{toDeclare}</span></div>
            </div>
            {history.length > 1 && (
              <div style={{ marginTop: 12 }}>
                <strong>Evolucion</strong>
                <svg viewBox="0 0 300 60" width="100%" height="70" role="img" aria-label={t("Evolucion del puntaje")} preserveAspectRatio="none">
                  <polyline fill="none" stroke="var(--accent, #6366f1)" strokeWidth="2" points={sparkPoints(history, "score_total", 300, 56)} />
                  <polyline fill="none" stroke="var(--success, #16a34a)" strokeWidth="2" strokeDasharray="4 3" points={sparkPoints(history, "score_verified", 300, 56)} />
                </svg>
                <div className="empty-hint">{t("{0} fotos guardadas, desde el {1}. Linea llena: con lo declarado. Linea punteada: solo lo verificado.", history.length, when(history[0].created_at))}</div>
              </div>
            )}
          </>
        )}
        <div className="gov-row-actions">
          <button className="btn-secondary" disabled={download.isPending || !canWrite} onClick={() => download.mutate("attestation")}>Descargar atestado firmado</button>
          <button className="btn-secondary" disabled={download.isPending} onClick={() => download.mutate("csv")}>Descargar cuestionario de seguro (CSV)</button>
          <button className="btn-secondary" disabled={snapshot.isPending || !canWrite} onClick={() => snapshot.mutate()}>Guardar foto de hoy</button>
          <label className="gov-row-check">
            <input type="checkbox" checked={onlyOpen} onChange={(e) => setOnlyOpen(e.target.checked)} /> Mostrar solo lo que hay que resolver
          </label>
        </div>
        {download.isSuccess && <p className="empty-hint">{t("Listo: se descargo {0}.", download.data)}</p>}
        {(download.isError || snapshot.isError) && <p className="error-text"><span className="error-detail">{connectionErrorDetail(download.error ?? snapshot.error)}</span></p>}
        {snapshot.isSuccess && <p className="empty-hint">Foto guardada y anotada en la cadena de custodia.</p>}
      </div>

      {areas.map((area) => {
        const rows = controls.filter((c) => c.area === area);
        const info = sum?.by_area[area];
        return (
          <div className="panel" key={area}>
            <h2>{t(rows[0].area_label)}{info ? ` · ${info.score}%` : ""}</h2>
            <div style={{ overflowX: "auto" }}>
              <table className="data-table">
                <thead><tr><th>Control</th><th>Estado</th><th>Origen</th><th>Detalle</th><th></th></tr></thead>
                <tbody>
                  {rows.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <div className="gov-hash">{c.id}</div>
                        {t(c.title)}
                        <div className="empty-hint">{c.refs.join(" · ")}</div>
                      </td>
                      <td><span className={CONTROL_STATUS_BADGE[c.status]}>{t(CONTROL_STATUS_LABEL[c.status])}</span></td>
                      <td>{t(BASIS_LABEL[c.basis])}</td>
                      <td>
                        <div>{msg(c.summary)}</div>
                        <details>
                          <summary>Por que importa y evidencia</summary>
                          <p>{t(c.why)}</p>
                          {c.evidence.length > 0 && (
                            <ul>
                              {c.evidence.map((e) => (
                                <li key={e.label}>{t(e.label)}: <strong>{observed(e.value)}</strong> <span className="empty-hint">({e.source})</span></li>
                              ))}
                            </ul>
                          )}
                          {c.declaration && (
                            <p className="empty-hint">
                              {c.declaration.valid_until
                                ? t("Declarado por {0} el {1}, vale hasta el {2}.", c.declaration.declared_by, when(c.declaration.declared_at), when(c.declaration.valid_until))
                                : t("Declarado por {0} el {1}.", c.declaration.declared_by, when(c.declaration.declared_at))}
                            </p>
                          )}
                        </details>
                        {declaring === c.id && (
                          <div className="inline-form" style={{ marginTop: 8, flexWrap: "wrap" }}>
                            <select value={form.answer} onChange={(e) => setForm({ ...form, answer: e.target.value as Form["answer"] })}>
                              <option value="yes">Si, lo cumplimos</option>
                              <option value="partial">Parcialmente</option>
                              <option value="no">No lo cumplimos</option>
                            </select>
                            <select value={form.months} onChange={(e) => setForm({ ...form, months: Number(e.target.value) })}>
                              <option value={6}>Vale 6 meses</option>
                              <option value={12}>Vale 12 meses</option>
                              <option value={24}>Vale 24 meses</option>
                            </select>
                            <textarea
                              rows={2} style={{ width: "100%" }} value={form.note} maxLength={2000}
                              placeholder={t("Que existe, donde esta y quien lo sabe (minimo 10 letras)")}
                              onChange={(e) => setForm({ ...form, note: e.target.value })}
                            />
                            <button className="btn-primary" disabled={declare.isPending || form.note.trim().length < 10} onClick={() => declare.mutate(c.id)}>Guardar declaracion</button>
                            <button className="btn-link" onClick={() => setDeclaring(null)}>Cancelar</button>
                            {declare.isError && <span className="error-detail">{connectionErrorDetail(declare.error)}</span>}
                          </div>
                        )}
                      </td>
                      <td>
                        {canWrite && canDeclare(c) && declaring !== c.id && (
                          <div className="gov-row-actions" style={{ marginTop: 0 }}>
                            <button className="btn-secondary" onClick={() => startDeclare(c)}>{c.declaration ? "Actualizar declaracion" : "Declarar"}</button>
                            {c.declaration && <button className="btn-link" disabled={undeclare.isPending} onClick={() => undeclare.mutate(c.id)}>Quitar declaracion</button>}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
      {s && controls.length === 0 && <div className="panel"><p className="empty-hint">No hay controles que resolver.</p></div>}

      {s && (
        <div className="panel">
          <h2>Cuestionario de ciberseguro (autocompletado)</h2>
          <p className="empty-hint">
            Las preguntas que casi todos los seguros hacen, respondidas con la evidencia de arriba. Cada aseguradora tiene su propio
            formulario: usa esto como base y completa lo que falte. Si una respuesta dice sin responder, falta evidencia o una declaracion.
          </p>
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead><tr><th>Pregunta</th><th>Respuesta</th><th>Se basa en</th></tr></thead>
              <tbody>
                {s.questionnaire.map((q) => (
                  <tr key={q.id}>
                    <td><span className="gov-hash">{q.id}</span> {t(q.text)}</td>
                    <td><span className={ANSWER_BADGE[q.answer]}>{t(ANSWER_LABEL[q.answer])}</span></td>
                    <td>{q.controls.map((c) => c.id).join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="panel">
        <h2>Como leer esto</h2>
        <ul>
          <li><strong>Verificado por TERO:</strong> sale de datos reales de TERO en el momento de la consulta. Si una fuente no responde, el control queda sin datos; nunca se da por cumplido.</li>
          <li><strong>Declarado por una persona:</strong> TERO guarda quien lo afirmo, cuando y hasta cuando vale, y lo anota en la cadena de custodia. No lo puede comprobar.</li>
          <li><strong>Atestado firmado:</strong> el resultado completo, firmado con la clave de la cadena de custodia. Se puede entregar a un auditor, que lo comprueba sin acceso a TERO.</li>
        </ul>
        <p className="empty-hint">
          Las medidas de la Res. AAIP 47/2018 son recomendaciones referenciales; la obligacion legal de seguridad es la del art. 9 de la
          Ley 25.326. Esto ordena evidencia, no reemplaza una consulta legal ni una auditoria.
        </p>
      </div>
    </div>
  );
}
