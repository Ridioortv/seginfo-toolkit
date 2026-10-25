import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { caseApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { connectionErrorDetail } from "../../utils/errors";
import { saveBlob } from "../../utils/download";
import {
  CLASSIFICATION_LABEL, VERDICT_TEXT,
  type SovereigntyProbe, type SovereigntyStatus,
} from "../../utils/trust";
import { currentLocale, t } from "../../i18n";

const CLASS_BADGE: Record<string, string> = {
  catalogado: "badge badge-success", configurado: "badge badge-medium", no_catalogado: "badge badge-critical",
};

const ISOLATE_COMMANDS = `docker compose down
docker compose -f docker-compose.yml -f docker-compose.aislado.yml up -d`;

function when(ts: string): string {
  return ts ? new Date(ts).toLocaleString(currentLocale()) : "-";
}

export default function Sovereignty() {
  const queryClient = useQueryClient();
  const claims = useAuthStore((s) => s.claims);
  const isAdmin = claims?.role === "admin";

  const status = useQuery({
    queryKey: ["sovereignty-status"],
    queryFn: async () => (await caseApi.get<SovereigntyStatus>("/sovereignty/status")).data,
    refetchInterval: 30_000,
  });
  const probe = useMutation({
    mutationFn: async () => (await caseApi.post<SovereigntyProbe>("/sovereignty/probe")).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sovereignty-status"] });
      queryClient.invalidateQueries({ queryKey: ["custody-entries"] });
    },
  });
  const attestation = useMutation({
    mutationFn: async () =>
      saveBlob(await caseApi.get<Blob>("/sovereignty/attestation", { responseType: "blob" }), "atestado-soberania.json"),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["custody-entries"] }),
  });

  const s = status.data;
  const verdict = s ? VERDICT_TEXT[s.verdict] : null;
  const lastProbe = probe.data ?? s?.probe ?? null;
  const external = (s?.destinations ?? []).filter((d) => d.recent);

  return (
    <div>
      <div className="panel">
        <h2>Prueba de soberania</h2>
        <p className="empty-hint">
          Que datos salen de tu infraestructura, hacia quien y para que. Cada servicio de TERO anota con que destinos
          externos habla (solo el nombre del sitio, nunca el contenido) y, en modo aislado, los bloquea antes de que salgan.
          La prueba de red intenta salir a internet de verdad: es lo que confirma el aislamiento.
        </p>
        {status.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(status.error)}</span></p>}
        {status.isLoading && <p className="empty-hint">Cargando...</p>}
        {s && verdict && (
          <>
            <div className={`gov-callout ${verdict.tone === "ok" ? "gov-ok" : verdict.tone === "bad" ? "gov-bad" : verdict.tone === "warn" ? "gov-warn" : ""}`}>
              <strong>{verdict.title}</strong>
              <div>{verdict.detail}</div>
              {s.notes.map((n) => (<div key={n.text + n.args.join()} className="empty-hint">{t(n.text, ...n.args)}</div>))}
            </div>
            <div className="cards-grid">
              <div className="stat-card"><span className="stat-label">Servicios que informan</span><span className="stat-value">{s.summary.services_reporting}/{s.summary.services_expected}</span></div>
              <div className="stat-card"><span className="stat-label">En modo aislado</span><span className="stat-value">{s.summary.isolated_services}</span></div>
              <div className="stat-card"><span className="stat-label">Destinos externos (30 dias)</span><span className="stat-value">{s.summary.external_destinations}</span></div>
              <div className="stat-card"><span className="stat-label">No catalogados</span><span className="stat-value">{s.summary.unknown_destinations}</span></div>
              <div className="stat-card"><span className="stat-label">Intentos bloqueados</span><span className="stat-value">{s.summary.blocked_attempts}</span></div>
            </div>
          </>
        )}
        <div className="gov-row-actions">
          {isAdmin && (
            <button className="btn-primary" disabled={probe.isPending} onClick={() => probe.mutate()}>
              {probe.isPending ? "Probando..." : "Probar salida a internet ahora"}
            </button>
          )}
          <button className="btn-secondary" disabled={attestation.isPending} onClick={() => attestation.mutate()}>
            Descargar atestado firmado
          </button>
        </div>
        {probe.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(probe.error)}</span></p>}
        {attestation.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(attestation.error)}</span></p>}
        {attestation.isSuccess && (
          <p className="empty-hint">{t("Listo: se descargo {0}. Para verificarlo, ejecuta el verificador sobre ese archivo.", attestation.data)}</p>
        )}
        {lastProbe && (
          <div style={{ marginTop: 14 }}>
            <strong>{t("Ultima prueba de red: {0} de {1} destinos alcanzables", lastProbe.reachable, lastProbe.total)}</strong>
            <span className="empty-hint"> {when(lastProbe.created_at)} {lastProbe.actor && `(${lastProbe.actor})`}</span>
            <table className="data-table">
              <thead><tr><th>Destino</th><th>Tipo</th><th>Resultado</th><th>Detalle</th></tr></thead>
              <tbody>
                {lastProbe.results.map((r) => (
                  <tr key={r.target + r.kind}>
                    <td className="gov-hash">{r.target}</td>
                    <td>{r.kind === "dns" ? "DNS" : "TCP"}</td>
                    <td><span className={r.informational ? "badge badge-neutral" : r.reachable ? "badge badge-critical" : "badge badge-success"}>{r.reachable ? "Alcanzable" : "Bloqueado"}</span></td>
                    <td>{r.detail}{r.informational && ` (${t("solo informativo")})`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Destinos externos</h2>
        {s && external.length === 0 && (
          <p className="empty-hint">Ningun servicio hablo con internet en los ultimos 30 dias (o todavia no informaron).</p>
        )}
        {external.length > 0 && (
          <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead><tr><th>Destino</th><th>Servicio</th><th>Para que</th><th>Que datos viajan</th><th>Veces</th><th>Bloqueadas</th><th>Ultima vez</th><th>Estado</th></tr></thead>
            <tbody>
              {external.map((d) => (
                <tr key={`${d.service}|${d.host}|${d.kind}`}>
                  <td className="gov-hash">{d.host}</td>
                  <td>{d.service}</td>
                  <td>{d.catalog?.purpose ?? d.purposes[0] ?? "-"}</td>
                  <td>{d.catalog?.sends ?? (d.classification === "configurado" ? "Lo que defina la integracion configurada" : "Desconocido")}</td>
                  <td>{d.count}</td>
                  <td>{d.blocked}</td>
                  <td>{when(d.last_seen)}</td>
                  <td><span className={CLASS_BADGE[d.classification]}>{CLASSIFICATION_LABEL[d.classification]}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Servicios</h2>
        {s && s.services.length === 0 && <p className="empty-hint">Todavia ningun servicio informo.</p>}
        {s && s.services.length > 0 && (
          <table className="data-table">
            <thead><tr><th>Servicio</th><th>Modo</th><th>Ultimo informe</th><th>Destinos que define un usuario</th></tr></thead>
            <tbody>
              {s.services.map((x) => (
                <tr key={x.service}>
                  <td>{x.service}</td>
                  <td><span className={x.isolated ? "badge badge-success" : "badge badge-neutral"}>{x.isolated ? "Aislado" : "Normal"}</span></td>
                  <td>{x.reporting ? when(x.last_seen) : `${when(x.last_seen)} (${t("sin informar")})`}</td>
                  <td>{x.configurable || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Como activar el modo aislado</h2>
        <p className="empty-hint">
          En la carpeta de TERO, en una terminal. Desde ese momento ningun servicio puede hablar con internet, y la
          prueba de arriba lo confirma. Se vuelve al modo normal con el mismo comando sin el archivo de aislado.
          Dejan de funcionar a proposito las consultas a NVD, CISA KEV, AbuseIPDB, crt.sh, GitHub, el SSO externo y los
          avisos en la nube; lo local sigue igual.
        </p>
        <code className="gov-code">{ISOLATE_COMMANDS}</code>
        {s && (
          <>
            <h3>Limites de esta prueba</h3>
            <ul>
              {s.limits.map((l) => (<li key={l}>{l}</li>))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
