import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { caseApi, vulnApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { SeverityBadge } from "../../components/Badge";
import { connectionErrorDetail } from "../../utils/errors";
import { saveBlob } from "../../utils/download";
import { CLOSURE_BADGE, CLOSURE_LABEL, formatHours, type ClosureStats, type ClosureVuln } from "../../utils/trust";
import { currentLocale, t } from "../../i18n";

const CAN_ACT = ["admin", "soc_manager", "analyst"];

function when(ts: string | null): string {
  return ts ? new Date(ts).toLocaleString(currentLocale()) : "-";
}

export default function Closure() {
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const canAct = CAN_ACT.includes(role);

  const stats = useQuery({
    queryKey: ["closure-stats"],
    queryFn: async () => (await vulnApi.get<ClosureStats>("/vulnerabilities/closure/stats")).data,
    refetchInterval: 15_000,
  });
  const list = useQuery({
    queryKey: ["closure-list"],
    queryFn: async () => {
      const [remediated, failed] = await Promise.all([
        vulnApi.get<ClosureVuln[]>("/vulnerabilities", { params: { status_filter: "remediated" } }),
        vulnApi.get<ClosureVuln[]>("/vulnerabilities", { params: { closure_status: "failed" } }),
      ]);
      const byId = new Map<string, ClosureVuln>();
      for (const v of [...failed.data, ...remediated.data]) byId.set(v.id, v);
      return [...byId.values()].sort((a, b) => (b.remediated_at ?? b.closure_checked_at ?? "").localeCompare(a.remediated_at ?? a.closure_checked_at ?? ""));
    },
    refetchInterval: 15_000,
  });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["closure-stats"] });
    queryClient.invalidateQueries({ queryKey: ["closure-list"] });
  };
  const verify = useMutation({
    mutationFn: async (id: string) => (await vulnApi.post(`/vulnerabilities/${id}/verify-closure`)).data,
    onSuccess: refresh,
  });
  const proof = useMutation({
    mutationFn: async (id: string) =>
      saveBlob(await caseApi.get<Blob>(`/closure/${id}/attestation`, { responseType: "blob" }), "prueba-cierre.json"),
  });

  const s = stats.data;
  const rows = list.data ?? [];

  return (
    <div>
      <div className="panel">
        <h2>Cierre verificado de vulnerabilidades</h2>
        <p className="empty-hint">
          Marcar una vulnerabilidad como remediada es solo una declaracion. Aca TERO repite el mismo escaneo que la encontro
          y solo la da por cerrada si ya no aparece. Si sigue ahi, la reabre sola. Cada resultado queda firmado en la cadena
          de custodia y se puede bajar como prueba. El tiempo de cierre real se mide hasta la verificacion, no hasta que
          alguien dijo que estaba lista.
        </p>
        {stats.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(stats.error)}</span></p>}
        {s && (
          <div className="cards-grid">
            <div className="stat-card"><span className="stat-label">Cierres verificados</span><span className="stat-value">{s.counts.verified ?? 0}</span></div>
            <div className="stat-card"><span className="stat-label">Cierres que fallaron</span><span className="stat-value">{s.counts.failed ?? 0}</span></div>
            <div className="stat-card"><span className="stat-label">En verificacion</span><span className="stat-value">{s.counts.pending ?? 0}</span></div>
            <div className="stat-card"><span className="stat-label">Remediadas sin verificar</span><span className="stat-value">{s.remediated_unverified}</span></div>
            <div className="stat-card"><span className="stat-label">Tiempo de cierre declarado</span><span className="stat-value">{formatHours(s.mttr_declared_hours)}</span></div>
            <div className="stat-card"><span className="stat-label">Tiempo de cierre real</span><span className="stat-value">{formatHours(s.mttr_real_hours)}</span></div>
            <div className="stat-card"><span className="stat-label">Cierres falsos</span><span className="stat-value">{s.false_closure_rate_pct === null ? "-" : `${s.false_closure_rate_pct}%`}</span></div>
          </div>
        )}
        {s && Object.keys(s.by_severity).length > 0 && (
          <table className="data-table">
            <thead><tr><th>Severidad</th><th>Verificadas</th><th>Fallaron</th><th>En verificacion</th><th>Sin verificar</th><th>Tiempo declarado</th><th>Tiempo real</th></tr></thead>
            <tbody>
              {Object.entries(s.by_severity).map(([sev, b]) => (
                <tr key={sev}>
                  <td><SeverityBadge value={sev} /></td><td>{b.verified}</td><td>{b.failed}</td><td>{b.pending}</td><td>{b.unverified}</td>
                  <td>{formatHours(b.mttr_declared_hours)}</td><td>{formatHours(b.mttr_real_hours)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Vulnerabilidades remediadas</h2>
        {list.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(list.error)}</span></p>}
        {list.isLoading && <p className="empty-hint">Cargando...</p>}
        {list.data && rows.length === 0 && (
          <p className="empty-hint">Todavia no hay vulnerabilidades remediadas. Al marcar una como remediada en Vulnerabilidades, la verificacion empieza sola.</p>
        )}
        {verify.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(verify.error)}</span></p>}
        {proof.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(proof.error)}</span></p>}
        {proof.isSuccess && <p className="empty-hint">{t("Listo: se descargo {0}. Para verificarlo, ejecuta el verificador sobre ese archivo.", proof.data)}</p>}
        {rows.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead><tr><th>Vulnerabilidad</th><th>Severidad</th><th>Remediada</th><th>Cierre</th><th>Detalle</th><th></th></tr></thead>
              <tbody>
                {rows.map((v) => (
                  <tr key={v.id}>
                    <td>{v.title}{v.cve_id && <div className="gov-hash">{v.cve_id}</div>}</td>
                    <td><SeverityBadge value={v.severity} /></td>
                    <td>{when(v.remediated_at)}</td>
                    <td><span className={CLOSURE_BADGE[v.closure_status] ?? "badge badge-neutral"}>{CLOSURE_LABEL[v.closure_status] ?? v.closure_status}</span></td>
                    <td>{v.closure_detail || "-"}</td>
                    <td>
                      <div className="gov-row-actions" style={{ marginTop: 0 }}>
                        {canAct && v.status === "remediated" && v.closure_status !== "pending" && (
                          <button className="btn-secondary" disabled={verify.isPending} onClick={() => verify.mutate(v.id)}>
                            {v.closure_status === "verified" ? "Volver a verificar" : "Verificar ahora"}
                          </button>
                        )}
                        {canAct && (v.closure_status === "verified" || v.closure_status === "failed") && (
                          <button className="btn-link" disabled={proof.isPending} onClick={() => proof.mutate(v.id)}>Descargar prueba</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Que significa cada estado</h2>
        <ul>
          <li><strong>Verificado:</strong> el escaneo repetido (mismo escaner, objetivo y opciones) termino y ya no detecta la vulnerabilidad.</li>
          <li><strong>Cierre fallido (reabierta):</strong> el escaneo repetido la volvio a detectar; TERO la reabrio y lo anoto en la cadena.</li>
          <li><strong>Sin concluir:</strong> el escaneo fallo o no termino a tiempo. Nunca se da por verificada sin un escaneo completo; podes reintentar.</li>
          <li><strong>No verificable:</strong> el hallazgo no viene de un escaneo que se pueda repetir (archivos subidos, agente remoto, nube, superficie de ataque, codigo).</li>
        </ul>
        <p className="empty-hint">
          Limite: verificado quiere decir que el escaneo repetido ya no la detecta. Si el objetivo estaba apagado y el escaner termino
          sin informar un error, podria dar un falso verificado; por eso el detalle muestra cuantos hallazgos tuvo el re-escaneo.
        </p>
      </div>
    </div>
  );
}
