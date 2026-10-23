import { useQuery } from "@tanstack/react-query";
import { vulnApi, siemApi, caseApi, purpleApi, assetApi, scanApi, soarApi, notificationApi } from "../services/api";
import type {
  VulnerabilityStatsOut,
  AlertOut,
  CaseOut,
  CoverageResult,
  AssetOut,
  ScanJobOut,
  AgentScanJobOut,
  PlaybookRunOut,
  NotifyLogOut,
} from "../types";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";
import Icon, { type IconName } from "../components/Icon";
import LogStorageWarning from "../components/LogStorageWarning";
import { useAuthStore } from "../store/auth";
import { currentLocale } from "../i18n";

type DashboardScan = {
  id: string;
  name: string;
  scanner_type: string;
  status: string;
  created_at: string;
  remote: boolean;
  inProgress: boolean;
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEVERITY_LABEL: Record<string, string> = {
  critical: "Criticas",
  high: "Altas",
  medium: "Medias",
  low: "Bajas",
  info: "Info",
};

function StatCard({
  icon,
  tone,
  label,
  value,
  hint,
}: {
  icon: IconName;
  tone: "danger" | "warning" | "success" | "info" | "accent";
  label: string;
  value: string | number;
  hint: string;
}) {
  return (
    <div className={`stat-card tone-${tone}`}>
      <span className="stat-icon"><Icon name={icon} /></span>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      <span className="stat-hint">{hint}</span>
    </div>
  );
}

// Anillo de cobertura (0-100). El valor llega de purple-team-service; se
// acota por si el backend devolviera algo fuera de rango.
function CoverageRing({ pct }: { pct: number | null }) {
  const R = 52;
  const C = 2 * Math.PI * R;
  const safe = pct === null ? 0 : Math.min(100, Math.max(0, pct));
  return (
    <div className="ring" role="img" aria-label={pct === null ? "Sin datos de cobertura" : `Cobertura ATT&CK ${safe}%`}>
      <svg viewBox="0 0 132 132">
        <defs>
          <linearGradient id="ringGradient" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#6d7dff" />
            <stop offset="100%" stopColor="#22d3ee" />
          </linearGradient>
        </defs>
        <circle className="ring-track" cx="66" cy="66" r={R} />
        <circle
          className="ring-value"
          cx="66"
          cy="66"
          r={R}
          strokeDasharray={`${(safe / 100) * C} ${C}`}
        />
      </svg>
      <div className="ring-center">
        <b>{pct === null ? "-" : `${safe}%`}</b>
        <span>cobertura</span>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const username = useAuthStore((st) => st.claims?.email ?? st.claims?.sub);
  const vulnStats = useQuery({
    queryKey: ["vuln-stats"],
    queryFn: async () => (await vulnApi.get<VulnerabilityStatsOut>("/vulnerabilities/stats")).data,
  });
  const alerts = useQuery({
    queryKey: ["alerts", "dashboard"],
    queryFn: async () => (await siemApi.get<AlertOut[]>("/alerts")).data,
  });
  const cases = useQuery({
    queryKey: ["cases", "dashboard"],
    queryFn: async () => (await caseApi.get<CaseOut[]>("/cases")).data,
  });
  const coverage = useQuery({
    queryKey: ["coverage-overall"],
    queryFn: async () => (await purpleApi.get<CoverageResult>("/coverage/overall")).data,
  });
  const assets = useQuery({
    queryKey: ["assets", "dashboard"],
    queryFn: async () => (await assetApi.get<AssetOut[]>("/assets")).data,
  });
  const scans = useQuery({
    queryKey: ["scans", "dashboard"],
    queryFn: async () => (await scanApi.get<ScanJobOut[]>("/scans")).data,
  });
  // Los escaneos remotos (los que ejecuta un agente LAN/WAN/Docker) viven en
  // otra tabla y otro endpoint (/agent-scans): sin esta consulta el dashboard
  // solo veia los escaneos locales y mostraba "sin escaneos" aunque hubiera
  // escaneos remotos corriendo o terminados.
  const agentScans = useQuery({
    queryKey: ["agent-scans", "dashboard"],
    queryFn: async () => (await scanApi.get<AgentScanJobOut[]>("/agent-scans")).data,
  });
  const playbookRuns = useQuery({
    queryKey: ["playbook-runs", "dashboard"],
    queryFn: async () => (await soarApi.get<PlaybookRunOut[]>("/runs")).data,
  });
  const notifyLogs = useQuery({
    queryKey: ["notify-logs", "dashboard"],
    queryFn: async () => (await notificationApi.get<NotifyLogOut[]>("/logs")).data,
  });

  const openAlerts = alerts.data?.filter((a) => a.status === "new" || a.status === "acknowledged").length ?? 0;
  const openCases = cases.data?.filter((c) => c.status === "open" || c.status === "in_progress").length ?? 0;
  const now = new Date().toISOString();
  const breachedCases = cases.data?.filter((c) => c.sla_due_at && c.sla_due_at < now && c.status !== "resolved" && c.status !== "closed").length ?? 0;
  const criticalAssets = assets.data?.filter((a) => a.criticality === "critical").length ?? 0;
  // Vista unica de ambos tipos. En remoto "en curso" es pending (en cola) o
  // assigned (un agente ya lo tomo); en local es pending o running.
  const allScans: DashboardScan[] = [
    ...(scans.data ?? []).map((s) => ({
      id: s.id,
      name: s.name || s.target,
      scanner_type: s.scanner_type,
      status: s.status,
      created_at: s.created_at,
      remote: false,
      inProgress: s.status === "running" || s.status === "pending",
    })),
    ...(agentScans.data ?? []).map((s) => ({
      id: s.id,
      name: s.name || s.target,
      scanner_type: s.scanner_type,
      status: s.status,
      created_at: s.created_at,
      remote: true,
      inProgress: s.status === "pending" || s.status === "assigned",
    })),
  ];
  const scansRunning = allScans.filter((s) => s.inProgress).length;
  const scansLoading = scans.isLoading || agentScans.isLoading;
  const scansError = scans.isError || agentScans.isError;

  // Servicios que fallaron al cargar -- se muestran como banner arriba y
  // cada stat-card que dependa de ese servicio cae a "-" en vez de a 0/0
  // (ver failedServiceLabels mas abajo: mostrar "0 alertas activas" cuando
  // en realidad siem-service no respondio es peor que mostrar nada, porque
  // da una falsa sensacion de que todo esta tranquilo).
  const serviceStatuses: { label: string; query: { isError: boolean; error: unknown } }[] = [
    { label: "vuln-service", query: vulnStats },
    { label: "siem-service", query: alerts },
    { label: "case-service", query: cases },
    { label: "purple-team-service", query: coverage },
    { label: "asset-service", query: assets },
    { label: "scan-service", query: scans },
    { label: "scan-service (escaneos remotos)", query: agentScans },
    { label: "soar-service", query: playbookRuns },
    { label: "notification-service", query: notifyLogs },
  ];
  const failedServices = serviceStatuses.filter((s) => s.query.isError);

  const recentScans = [...allScans]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);
  const recentRuns = [...(playbookRuns.data ?? [])]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);
  const recentNotifications = [...(notifyLogs.data ?? [])]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);

  return (
    <div>
      <section className="dash-hero">
        <div>
          <h1>{username ? `Hola, ${username.split("@")[0]}` : "Hola"}</h1>
          <p>Vista general del estado de seguridad defensiva de tu organizacion.</p>
        </div>
        <span className="dash-hero-chip">
          <span className="status-dot" aria-hidden="true" />
          {scansLoading || scansError ? "Escaneos: sin datos" : scansRunning > 0 ? (scansRunning === 1 ? "1 escaneo en curso" : `${scansRunning} escaneos en curso`) : "Sin escaneos en curso"}
        </span>
      </section>
      <LogStorageWarning />
      {failedServices.length > 0 && (
        <div className="panel">
          <p className="error-text">
            {`${failedServices.length === 1 ? "No se pudo conectar con este servicio" : "No se pudo conectar con estos servicios"}: ${failedServices.map((s) => s.label).join(", ")}.`}{" "}
            {failedServices.length === 1
              ? 'Las metricas que dependen de el muestran "-" en vez de 0 para no confundir "sin datos" con "no responde".'
              : 'Las metricas que dependen de ellos muestran "-" en vez de 0 para no confundir "sin datos" con "no responde".'}
          </p>
          {failedServices.map((s) => (
            <p key={s.label} className="error-text" style={{ marginTop: 4 }}>
              {s.label}: <span className="error-detail">{connectionErrorDetail(s.query.error)}</span>
            </p>
          ))}
        </div>
      )}
      <div className="kpi-grid">
        <StatCard
          icon="bug"
          tone="danger"
          label="Vulnerabilidades abiertas"
          value={vulnStats.data?.total ?? "-"}
          hint={`${vulnStats.data?.kev_count ?? 0} en catalogo CISA KEV`}
        />
        <StatCard
          icon="activity"
          tone="warning"
          label="Alertas SIEM activas"
          value={alerts.isLoading || alerts.isError ? "-" : openAlerts}
          hint={`de ${alerts.isError ? "-" : alerts.data?.length ?? 0} totales`}
        />
        <StatCard
          icon="briefcase"
          tone="accent"
          label="Casos abiertos"
          value={cases.isLoading || cases.isError ? "-" : openCases}
          hint={`${cases.isError ? "-" : breachedCases} con SLA vencido`}
        />
        <StatCard
          icon="target"
          tone="success"
          label="Cobertura ATT&CK"
          value={coverage.data ? `${coverage.data.coverage_pct}%` : "-"}
          hint={`${coverage.data?.gaps.length ?? 0} tecnicas sin deteccion`}
        />
        <StatCard
          icon="assets"
          tone="info"
          label="Activos inventariados"
          value={assets.isLoading || assets.isError ? "-" : assets.data?.length ?? 0}
          hint={`${assets.isError ? "-" : criticalAssets} criticos`}
        />
        <StatCard
          icon="scans"
          tone="accent"
          label="Escaneos en curso"
          value={scansLoading || scansError ? "-" : scansRunning}
          hint={`de ${scansError ? "-" : allScans.length} totales`}
        />
      </div>

      <div className="dash-grid">
        <div className="panel">
          <h2>Vulnerabilidades por severidad</h2>
          {vulnStats.data ? (
            (() => {
              const bySev = vulnStats.data.by_severity;
              const known = SEVERITY_ORDER.filter((k) => (bySev[k] ?? 0) > 0);
              const others = Object.entries(bySev).filter(([k, n]) => !(SEVERITY_ORDER as readonly string[]).includes(k) && n > 0);
              const total = known.reduce((a, k) => a + bySev[k], 0) + others.reduce((a, [, n]) => a + n, 0);
              if (total === 0) return <p className="empty-hint">Sin vulnerabilidades abiertas.</p>;
              return (
                <>
                  <div className="sev-bar" role="img" aria-label="Distribucion de vulnerabilidades por severidad">
                    {known.map((k) => (
                      <span key={k} className={`sev-${k}`} style={{ flexGrow: bySev[k] }} title={`${SEVERITY_LABEL[k]}: ${bySev[k]}`} />
                    ))}
                    {others.map(([k, n]) => (
                      <span key={k} className="sev-info" style={{ flexGrow: n }} title={`${k}: ${n}`} />
                    ))}
                  </div>
                  <ul className="sev-legend">
                    {known.map((k) => (
                      <li key={k}><i className={`sev-${k}`} />{SEVERITY_LABEL[k]}<b>{bySev[k]}</b></li>
                    ))}
                    {others.map(([k, n]) => (
                      <li key={k}><i className="sev-info" />{k}<b>{n}</b></li>
                    ))}
                  </ul>
                </>
              );
            })()
          ) : (
            <p className="empty-hint">{vulnStats.isError ? "No se pudo cargar." : "Cargando..."}</p>
          )}
        </div>

        <div className="panel">
          <h2>Cobertura MITRE ATT&amp;CK</h2>
          <div className="ring-wrap">
            <CoverageRing pct={coverage.data ? coverage.data.coverage_pct : null} />
            <div>
              <p style={{ margin: "0 0 4px", fontWeight: 600 }}>
                {coverage.data ? `${coverage.data.gaps.length} tecnicas sin deteccion` : "Sin datos todavia"}
              </p>
              <p className="empty-hint" style={{ margin: 0, padding: 0 }}>
                {coverage.data ? `${coverage.data.covered_count} de ${coverage.data.total_techniques} tecnicas tienen al menos una regla de deteccion.` : "Porcentaje de tecnicas ATT&CK con al menos una regla de deteccion."}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <h2>Brechas de deteccion MITRE ATT&amp;CK</h2>
        {coverage.data?.gaps.length ? (
          <ul className="kv-list">
            {coverage.data.gaps.map((g) => (
              <li key={g.technique_id}><span>{g.technique_id} - {g.name}</span><span>{g.tactic}</span></li>
            ))}
          </ul>
        ) : (
          <p className="empty-hint">Sin datos de cobertura todavia (o sin brechas detectadas).</p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos recientes</h2>
        {recentScans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Estado</th>
                <th>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td>{s.scanner_type}{s.remote ? " (remoto)" : ""}</td>
                  <td><StatusBadge value={s.status} /></td>
                  <td>{new Date(s.created_at).toLocaleString(currentLocale())}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin escaneos todavia.</p>
        )}
      </div>

      <div className="panel">
        <h2>Playbooks SOAR ejecutados recientemente</h2>
        {recentRuns.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Playbook</th>
                <th>Estado</th>
                <th>Disparado por</th>
                <th>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {recentRuns.map((r) => (
                <tr key={r.id}>
                  <td>{r.playbook_name}</td>
                  <td><StatusBadge value={r.status} /></td>
                  <td>{r.triggered_by || "-"}</td>
                  <td>{new Date(r.created_at).toLocaleString(currentLocale())}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin playbooks ejecutados todavia.</p>
        )}
      </div>

      <div className="panel">
        <h2>Notificaciones recientes</h2>
        {recentNotifications.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Asunto</th>
                <th>Canal</th>
                <th>Estado</th>
                <th>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {recentNotifications.map((n) => (
                <tr key={n.id}>
                  <td>{n.subject}</td>
                  <td>{n.channel_type}</td>
                  <td><StatusBadge value={n.status} /></td>
                  <td>{new Date(n.created_at).toLocaleString(currentLocale())}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin notificaciones todavia.</p>
        )}
      </div>
    </div>
  );
}
