import { useQuery } from "@tanstack/react-query";
import { vulnApi, siemApi, caseApi, purpleApi } from "../services/api";
import type { VulnerabilityStatsOut, AlertOut, CaseOut, CoverageResult } from "../types";
import PageHeader from "../components/PageHeader";

export default function Dashboard() {
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

  const openAlerts = alerts.data?.filter((a) => a.status === "new" || a.status === "acknowledged").length ?? 0;
  const openCases = cases.data?.filter((c) => c.status === "open" || c.status === "in_progress").length ?? 0;
  const now = new Date().toISOString();
  const breachedCases = cases.data?.filter((c) => c.sla_due_at && c.sla_due_at < now && c.status !== "resolved" && c.status !== "closed").length ?? 0;

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Vista general del estado de seguridad defensiva" />
      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Vulnerabilidades abiertas</span>
          <span className="stat-value">{vulnStats.data?.total ?? "-"}</span>
          <span className="stat-hint">{vulnStats.data?.kev_count ?? 0} en catalogo CISA KEV</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Alertas SIEM activas</span>
          <span className="stat-value">{alerts.isLoading ? "-" : openAlerts}</span>
          <span className="stat-hint">de {alerts.data?.length ?? 0} totales</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Casos abiertos</span>
          <span className="stat-value">{cases.isLoading ? "-" : openCases}</span>
          <span className="stat-hint">{breachedCases} con SLA vencido</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Cobertura ATT&amp;CK</span>
          <span className="stat-value">{coverage.data ? `${coverage.data.coverage_pct}%` : "-"}</span>
          <span className="stat-hint">{coverage.data?.gaps.length ?? 0} tecnicas sin deteccion</span>
        </div>
      </div>

      <div className="panel">
        <h2>Vulnerabilidades por severidad</h2>
        <ul className="kv-list">
          {vulnStats.data && Object.entries(vulnStats.data.by_severity).map(([sev, count]) => (
            <li key={sev}><span>{sev}</span><span>{count}</span></li>
          ))}
        </ul>
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
    </div>
  );
}
