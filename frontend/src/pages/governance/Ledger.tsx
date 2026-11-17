import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { coderepoApi } from "../../services/api";
import { connectionErrorDetail } from "../../utils/errors";
import {
  EVENT_LABEL, shortHash, summarizePayload, type AnchorOut, type LedgerPage, type VerifyOut,
} from "../../utils/governance";
import { currentLocale, t } from "../../i18n";

const PAGE_SIZE = 25;

async function download(path: string, fallbackName: string) {
  const resp = await coderepoApi.get<Blob>(path, { responseType: "blob" });
  const disposition = String(resp.headers["content-disposition"] ?? "");
  const name = /filename="?([^";]+)"?/.exec(disposition)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(resp.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function Ledger() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(0);
  const [eventType, setEventType] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [anchor, setAnchor] = useState<AnchorOut | null>(null);
  const [expectedCount, setExpectedCount] = useState("");
  const [expectedHead, setExpectedHead] = useState("");
  const [exportError, setExportError] = useState<unknown>(null);

  const ledger = useQuery({
    queryKey: ["gov-ledger", page, eventType],
    queryFn: async () =>
      (await coderepoApi.get<LedgerPage>("/governance/ledger", {
        params: { limit: PAGE_SIZE, offset: page * PAGE_SIZE, ...(eventType ? { event_type: eventType } : {}) },
      })).data,
  });

  const verify = useMutation({
    mutationFn: async () =>
      (await coderepoApi.get<VerifyOut>("/governance/ledger/verify", {
        params: {
          ...(expectedCount.trim() ? { expected_count: Number(expectedCount) } : {}),
          ...(expectedHead.trim() ? { expected_head: expectedHead.trim() } : {}),
        },
      })).data,
  });
  const makeAnchor = useMutation({
    mutationFn: async () => (await coderepoApi.get<AnchorOut>("/governance/ledger/anchor")).data,
    onSuccess: (a) => { setAnchor(a); queryClient.invalidateQueries({ queryKey: ["gov-metrics"] }); },
  });

  const total = ledger.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const v = verify.data;

  async function onExport(format: "json" | "csv") {
    setExportError(null);
    try {
      await download(`/governance/ledger/export?format=${format}`, `tero-registro.${format}`);
    } catch (e) {
      setExportError(e);
    }
  }

  return (
    <div>
      <div className="panel">
        <h2>Registro auditable</h2>
        <p className="empty-hint">
          Todo lo que importa queda anotado aca: cada cambio registrado, cada declaracion de origen, cada revision,
          cada evaluacion de la compuerta y cada cambio de politica. Las entradas se encadenan (cada una guarda la huella de
          la anterior) y se firman con una clave que no esta en la base de datos: nadie puede editar ni borrar el pasado sin
          que la verificacion lo detecte. Solo se agrega, nunca se modifica.
        </p>
        <div className="gov-row-actions">
          <button className="btn-primary" disabled={verify.isPending} onClick={() => verify.mutate()}>
            {verify.isPending ? "Verificando..." : "Verificar el registro ahora"}
          </button>
          <button className="btn-secondary" onClick={() => onExport("json")}>Descargar JSON (verificable)</button>
          <button className="btn-secondary" onClick={() => onExport("csv")}>Descargar CSV</button>
        </div>
        {verify.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(verify.error)}</span></p>}
        {exportError != null && <p className="error-text"><span className="error-detail">{connectionErrorDetail(exportError)}</span></p>}
        {v && (
          <div className={`gov-callout ${v.ok ? "gov-ok" : "gov-bad"}`} style={{ marginTop: 14 }}>
            {v.ok ? (
              <>
                <strong>Registro integro.</strong> {t("{0} entradas, encadenadas y firmadas correctamente.", v.entries)}
                {v.anchor_checked && " Coincide con el ancla guardada."}
                <div className="gov-hash">Huella final: {v.head_hash}</div>
              </>
            ) : (
              <>
                <strong>El registro fue alterado.</strong> {v.broken_at_seq != null && t("Primera entrada con problema: #{0}.", v.broken_at_seq)} {v.reason}
              </>
            )}
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Ancla externa</h2>
        <p className="empty-hint">
          Si alguien con acceso a la base borrara las ultimas entradas, desde adentro no se nota. Para cubrir eso, genera un
          ancla (cantidad de entradas y huella final) y guardala por fuera de TERO: en un mail, un ticket o una carpeta
          aparte. Despues podes verificar el registro contra esa ancla.
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
        <h2>Entradas</h2>
        <div className="inline-form">
          <select value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(0); setOpen(null); }}>
            <option value="">Todos los eventos</option>
            {Object.entries(EVENT_LABEL).map(([k, label]) => (<option key={k} value={k}>{label}</option>))}
          </select>
        </div>
        {ledger.isLoading && <p className="empty-hint">Cargando...</p>}
        {ledger.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(ledger.error)}</span></p>}
        {ledger.data && ledger.data.items.length === 0 && <p className="empty-hint">El registro esta vacio: se llena solo al escanear repositorios y al usar esta pantalla.</p>}
        {ledger.data && ledger.data.items.length > 0 && (
          <table className="data-table">
            <thead><tr><th>#</th><th>Fecha</th><th>Evento</th><th>Quien</th><th>Detalle</th><th>Huella</th><th></th></tr></thead>
            <tbody>
              {ledger.data.items.map((e) => (
                <Fragment key={e.seq}>
                  <tr>
                    <td>{e.seq}</td>
                    <td>{new Date(e.ts).toLocaleString(currentLocale())}</td>
                    <td>{EVENT_LABEL[e.event_type] ?? e.event_type}</td>
                    <td>{e.actor}</td>
                    <td>{summarizePayload(e.event_type, e.payload, t)}</td>
                    <td className="gov-hash">{shortHash(e.entry_hash)}</td>
                    <td><button className="btn-link" onClick={() => setOpen(open === e.seq ? null : e.seq)}>{open === e.seq ? "Cerrar" : "Ver"}</button></td>
                  </tr>
                  {open === e.seq && (
                    <tr><td colSpan={7}>
                      <code className="gov-code">{JSON.stringify({ ...e }, null, 2)}</code>
                    </td></tr>
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
