import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { vulnApi } from "../services/api";
import type { VulnerabilityOut, VulnerabilityStatsOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

const TRIAGE_ACTIONS: { status: string; label: string }[] = [
  { status: "confirmed", label: "Confirmar" },
  { status: "false_positive", label: "Falso positivo" },
  { status: "accepted_risk", label: "Aceptar riesgo" },
  { status: "remediated", label: "Marcar remediado" },
];

export default function Vulnerabilities() {
  const queryClient = useQueryClient();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [triageActionError, setTriageActionError] = useState<unknown>(null);

  const stats = useQuery({
    queryKey: ["vuln-stats", "page"],
    queryFn: async () => (await vulnApi.get<VulnerabilityStatsOut>("/vulnerabilities/stats")).data,
  });
  const vulns = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => (await vulnApi.get<VulnerabilityOut[]>("/vulnerabilities")).data,
  });

  const triage = useMutation({
    mutationFn: async ({ id, status: newStatus }: { id: string; status: string }) =>
      (await vulnApi.patch<VulnerabilityOut>(`/vulnerabilities/${id}/triage`, { status: newStatus })).data,
    onSuccess: () => {
      setTriageActionError(null);
      queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
      queryClient.invalidateQueries({ queryKey: ["vuln-stats", "page"] });
    },
    onError: (err: unknown) => setTriageActionError(err),
  });

  return (
    <div>
      <PageHeader title="Vulnerabilidades" subtitle="Hallazgos enriquecidos con CVSS/EPSS/CISA-KEV y priorizados, con pasos de remediacion sugeridos" />

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
        {vulns.isError && (
          <p className="error-text">
            No se pudo conectar con vuln-service.{" "}
            <span className="error-detail">{connectionErrorDetail(vulns.error)}</span>
          </p>
        )}
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
                <th>Estado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {vulns.data.map((v) => (
                <Fragment key={v.id}>
                  <tr>
                    <td className="mono">{v.cve_id ?? "-"}</td>
                    <td>{v.title}</td>
                    <td><SeverityBadge value={v.severity} /></td>
                    <td>{v.cvss_score ?? "-"}</td>
                    <td>{v.epss_score ?? "-"}</td>
                    <td>{v.is_kev ? "si" : "no"}</td>
                    <td>{v.priority_score?.toFixed(1)}</td>
                    <td>{v.package || "-"}</td>
                    <td><StatusBadge value={v.status} /></td>
                    <td>
                      <button className="btn-link" onClick={() => setExpandedId(expandedId === v.id ? null : v.id)}>
                        {expandedId === v.id ? "Ocultar remediacion" : "Ver remediacion"}
                      </button>
                    </td>
                  </tr>
                  {expandedId === v.id && (
                    <tr key={`${v.id}-detail`}>
                      <td colSpan={10} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
                        <strong>Pasos de remediacion sugeridos:</strong>
                        <ol style={{ marginTop: 6, marginBottom: 10 }}>
                          {v.remediation_steps.map((step, idx) => (
                            <li key={idx}>{step}</li>
                          ))}
                        </ol>
                        {v.status !== "remediated" && v.status !== "false_positive" && (
                          <div className="inline-form">
                            {TRIAGE_ACTIONS.map((action) => (
                              <button
                                key={action.status}
                                className="btn-secondary"
                                disabled={triage.isPending}
                                onClick={() => triage.mutate({ id: v.id, status: action.status })}
                              >
                                {action.label}
                              </button>
                            ))}
                          </div>
                        )}
                        {v.triage_note && (
                          <p className="empty-hint" style={{ marginTop: 8 }}>
                            Nota de triage: {v.triage_note} {v.triaged_by && `(por ${v.triaged_by})`}
                          </p>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {vulns.data.length === 0 && (
                <tr><td colSpan={10} className="empty-hint">Sin vulnerabilidades ingeridas todavia -- lanza un escaneo desde Activos o Escaneos.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {triageActionError != null && (
          <p className="error-text">
            No se pudo actualizar el triage.{" "}
            <span className="error-detail">{connectionErrorDetail(triageActionError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
