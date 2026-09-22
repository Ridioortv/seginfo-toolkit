import { useQuery } from "@tanstack/react-query";
import { vulnApi } from "../services/api";
import type { VulnerabilityOut, VulnerabilityStatsOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge } from "../components/Badge";

export default function Vulnerabilities() {
  const stats = useQuery({
    queryKey: ["vuln-stats", "page"],
    queryFn: async () => (await vulnApi.get<VulnerabilityStatsOut>("/vulnerabilities/stats")).data,
  });
  const vulns = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => (await vulnApi.get<VulnerabilityOut[]>("/vulnerabilities")).data,
  });

  return (
    <div>
      <PageHeader title="Vulnerabilidades" subtitle="Hallazgos enriquecidos con CVSS/EPSS/CISA-KEV y priorizados" />

      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Total</span>
          <span className="stat-value">{stats.data?.total ?? "-"}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">En CISA KEV</span>
          <span className="stat-value">{stats.data?.kev_count ?? "-"}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Prioridad promedio</span>
          <span className="stat-value">{stats.data?.avg_priority_score?.toFixed(1) ?? "-"}</span>
        </div>
      </div>

      <div className="panel">
        {vulns.isLoading && <p className="empty-hint">Cargando...</p>}
        {vulns.isError && <p className="error-text">No se pudo conectar con vuln-service.</p>}
        {vulns.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE</th>
                <th>Titulo</th>
                <th>Severidad</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th>Prioridad</th>
                <th>Paquete</th>
              </tr>
            </thead>
            <tbody>
              {vulns.data.map((v) => (
                <tr key={v.id}>
                  <td className="mono">{v.cve_id ?? "-"}</td>
                  <td>{v.title}</td>
                  <td><SeverityBadge value={v.severity} /></td>
                  <td>{v.cvss_score ?? "-"}</td>
                  <td>{v.epss_score ?? "-"}</td>
                  <td>{v.is_kev ? "si" : "no"}</td>
                  <td>{v.priority_score?.toFixed(1)}</td>
                  <td>{v.package || "-"}</td>
                </tr>
              ))}
              {vulns.data.length === 0 && (
                <tr><td colSpan={8} className="empty-hint">Sin vulnerabilidades ingeridas todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
