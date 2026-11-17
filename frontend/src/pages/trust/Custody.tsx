import { Fragment, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { caseApi } from "../../services/api";
import { connectionErrorDetail } from "../../utils/errors";
import { saveBlob } from "../../utils/download";
import {
  CUSTODY_EVENT_LABEL, shortHash, summarizeCustody,
  type CustodyAnchor, type CustodyPage, type CustodyStatus, type CustodyVerify,
} from "../../utils/trust";
import type { CaseOut } from "../../types";
import { currentLocale, t } from "../../i18n";

const PAGE_SIZE = 25;

export default function Custody() {
  const [page, setPage] = useState(0);
  const [eventType, setEventType] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [caseId, setCaseId] = useState("");
  const [anchor, setAnchor] = useState<CustodyAnchor | null>(null);
  const [expectedCount, setExpectedCount] = useState("");
  const [expectedHead, setExpectedHead] = useState("");
  const [exported, setExported] = useState<string | null>(null);

  const status = useQuery({
    queryKey: ["custody-status"],
    queryFn: async () => (await caseApi.get<CustodyStatus>("/custody/status")).data,
  });
  const entries = useQuery({
    queryKey: ["custody-entries", page, eventType],
    queryFn: async () =>
      (await caseApi.get<CustodyPage>("/custody/entries", {
        params: { limit: PAGE_SIZE, offset: page * PAGE_SIZE, ...(eventType ? { event_type: eventType } : {}) },
      })).data,
  });
  const cases = useQuery({
    queryKey: ["cases"],
    queryFn: async () => (await caseApi.get<CaseOut[]>("/cases")).data,
  });

  const verify = useMutation({
    mutationFn: async () =>
      (await caseApi.get<CustodyVerify>("/custody/verify", {
        params: {
          ...(expectedCount.trim() ? { expected_count: Number(expectedCount) } : {}),
          ...(expectedHead.trim() ? { expected_head: expectedHead.trim() } : {}),
        },
      })).data,
  });
  const makeAnchor = useMutation({
    mutationFn: async () => (await caseApi.get<CustodyAnchor>("/custody/anchor")).data,
    onSuccess: setAnchor,
  });
  const exportPackage = useMutation({
    mutationFn: async () => {
      const resp = await caseApi.post<Blob>(`/custody/cases/${caseId}/package`, null, { responseType: "blob" });
      return saveBlob(resp, "evidencia-caso.zip");
    },
    onSuccess: (name) => { setExported(name); entries.refetch(); status.refetch(); },
  });
  const downloadVerifier = useMutation({
    mutationFn: async () => saveBlob(await caseApi.get<Blob>("/custody/verifier", { responseType: "blob" }), "verificar_evidencia.py"),
  });

  const total = entries.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const v = verify.data;
  const s = status.data;

  return (
    <div>
      <div className="panel">
        <h2>Cadena de custodia digital</h2>
        <p className="empty-hint">
          Todo lo que pasa en un caso (alertas, acciones de respuesta, cambios de estado, escaneos, cierres de
          vulnerabilidades) queda anotado en una cadena: cada evento guarda la huella del anterior y se firma con una
          clave. Un auditor o un juez puede comprobar que nada se cambio ni se borro despues, con un programa
          independiente y sin acceso a TERO.
        </p>
        {status.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(status.error)}</span></p>}
        {s && (
          <>
            <div className="gov-form-grid">
              <div><label>Eventos en la cadena</label><div>{s.entries}</div></div>
              <div><label>Algoritmo</label><div>{s.algorithm}</div></div>
              <div><label>Huella de la clave publica</label><div className="gov-hash">{s.key_fingerprint}</div></div>
            </div>
            <label className="empty-hint" style={{ display: "block", marginBottom: 4 }}>Clave publica (se la das al auditor)</label>
            <code className="gov-code">{s.public_key}</code>
            {s.key_derived_from_jwt && (
              <div className="gov-callout gov-warn">
                <strong>Recomendado:</strong> la clave de firma se deriva del secreto del servidor. Para que quede separada,
                define <code>CUSTODY_SIGNING_SEED</code> en el archivo .env (un texto largo y secreto) y reinicia
                case-service. Hacelo antes de empezar a usar la cadena: cambiarla despues invalida las firmas anteriores.
              </div>
            )}
          </>
        )}
        <div className="gov-row-actions">
          <button className="btn-primary" disabled={verify.isPending} onClick={() => verify.mutate()}>
            {verify.isPending ? "Verificando..." : "Verificar la cadena ahora"}
          </button>
          <button className="btn-secondary" disabled={downloadVerifier.isPending} onClick={() => downloadVerifier.mutate()}>
            Descargar el verificador independiente
          </button>
        </div>
        {verify.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(verify.error)}</span></p>}
        {v && (
          <div className={`gov-callout ${v.ok ? "gov-ok" : "gov-bad"}`} style={{ marginTop: 14 }}>
            {v.ok ? (
              <>
                <strong>Cadena integra.</strong> {t("{0} entradas, encadenadas y firmadas correctamente.", v.entries)}
                {v.anchor_checked && " Coincide con el ancla guardada."}
                <div className="gov-hash">Huella final: {v.head_hash}</div>
              </>
            ) : (
              <>
                <strong>La cadena fue alterada.</strong> {v.broken_at_seq != null && t("Primera entrada con problema: #{0}.", v.broken_at_seq)} {v.reason}
              </>
            )}
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Paquete de evidencia de un caso</h2>
        <p className="empty-hint">
          Genera un .zip con la ficha del caso, todos sus eventos firmados y un verificador. Del resto de la cadena solo
          incluye huellas: se puede comprobar que esta entera sin ver datos de otros casos. Cada exportacion queda anotada
          en la cadena. Prueba lo que el sistema registro y cuando; no que los hechos sean verdaderos.
        </p>
        <div className="inline-form">
          <select value={caseId} onChange={(e) => { setCaseId(e.target.value); setExported(null); }}>
            <option value="">Elegi un caso...</option>
            {(cases.data ?? []).map((c) => (<option key={c.id} value={c.id}>{c.title}</option>))}
          </select>
          <button className="btn-primary" disabled={!caseId || exportPackage.isPending} onClick={() => exportPackage.mutate()}>
            {exportPackage.isPending ? "Generando..." : "Exportar evidencia"}
          </button>
        </div>
        {exportPackage.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(exportPackage.error)}</span></p>}
        {exported && <p className="empty-hint">{t("Listo: se descargo {0}. Para verificarlo, ejecuta el verificador sobre ese archivo.", exported)}</p>}
      </div>

      <div className="panel">
        <h2>Ancla externa</h2>
        <p className="empty-hint">
          Si alguien con acceso a la base borrara los ultimos eventos, desde adentro no se nota. Genera un ancla (cantidad y
          huella final, firmada) y guardala por fuera de TERO: en un mail, un ticket o una carpeta aparte. Despues podes
          verificar la cadena contra esa ancla.
        </p>
        <div className="gov-row-actions">
          <button className="btn-secondary" disabled={makeAnchor.isPending} onClick={() => makeAnchor.mutate()}>Generar ancla</button>
        </div>
        {anchor && (
          <code className="gov-code">
            {`entradas: ${anchor.entries}\nhuella_final: ${anchor.head_hash}\ngenerada: ${anchor.generated_at}\nfirma: ${anchor.signature}`}
          </code>
        )}
        <div className="gov-form-grid" style={{ marginTop: 12 }}>
          <div><label>Cantidad de entradas guardada</label><input inputMode="numeric" value={expectedCount} onChange={(e) => setExpectedCount(e.target.value)} placeholder="ej. 128" /></div>
          <div><label>Huella final guardada</label><input value={expectedHead} onChange={(e) => setExpectedHead(e.target.value)} placeholder="64 caracteres" /></div>
        </div>
        <button className="btn-secondary" disabled={verify.isPending || (!expectedCount.trim() && !expectedHead.trim())} onClick={() => verify.mutate()}>
          Verificar contra el ancla
        </button>
      </div>

      <div className="panel">
        <h2>Eventos</h2>
        <div className="inline-form">
          <select value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(0); setOpen(null); }}>
            <option value="">Todos los eventos</option>
            {Object.entries(CUSTODY_EVENT_LABEL).map(([k, label]) => (<option key={k} value={k}>{label}</option>))}
          </select>
        </div>
        {entries.isLoading && <p className="empty-hint">Cargando...</p>}
        {entries.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(entries.error)}</span></p>}
        {entries.data && entries.data.items.length === 0 && (
          <p className="empty-hint">La cadena esta vacia: se llena sola cuando se crean casos, saltan alertas o se hacen escaneos.</p>
        )}
        {entries.data && entries.data.items.length > 0 && (
          <table className="data-table">
            <thead><tr><th>#</th><th>Fecha</th><th>Evento</th><th>Quien</th><th>Detalle</th><th>Huella</th><th></th></tr></thead>
            <tbody>
              {entries.data.items.map((e) => (
                <Fragment key={e.seq}>
                  <tr>
                    <td>{e.seq}</td>
                    <td>{new Date(e.ts).toLocaleString(currentLocale())}</td>
                    <td>{CUSTODY_EVENT_LABEL[e.event_type] ?? e.event_type}</td>
                    <td>{e.actor}</td>
                    <td>{summarizeCustody(e.event_type, e.payload, t)}</td>
                    <td className="gov-hash">{shortHash(e.entry_hash)}</td>
                    <td><button className="btn-link" onClick={() => setOpen(open === e.seq ? null : e.seq)}>{open === e.seq ? "Cerrar" : "Ver"}</button></td>
                  </tr>
                  {open === e.seq && (
                    <tr><td colSpan={7}><code className="gov-code">{JSON.stringify(e, null, 2)}</code></td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
        {total > PAGE_SIZE && (
          <div className="gov-pager">
            <span>{t("{0} entradas", total)}</span>
            <button className="btn-secondary" disabled={page === 0} onClick={() => { setPage(page - 1); setOpen(null); }}>Anterior</button>
            <span>{t("Pagina {0} de {1}", page + 1, pages)}</span>
            <button className="btn-secondary" disabled={page + 1 >= pages} onClick={() => { setPage(page + 1); setOpen(null); }}>Siguiente</button>
          </div>
        )}
      </div>
    </div>
  );
}
