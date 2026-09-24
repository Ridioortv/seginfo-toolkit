import { useQuery } from "@tanstack/react-query";
import { caseApi } from "../services/api";
import type { CaseOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";
import { isSlaBreached } from "../utils/sla";

export default function Cases() {
  const cases = useQuery({
    queryKey: ["cases"],
    queryFn: async () => (await caseApi.get<CaseOut[]>("/cases")).data,
  });

  return (
    <div>
      <PageHeader title="Casos" subtitle="Gestion de incidentes estilo ITSM con SLA por prioridad y timeline de auditoria" />
      <div className="panel">
        {cases.isLoading && <p className="empty-hint">Cargando...</p>}
        {cases.isError && (
          <p className="error-text">
            No se pudo conectar con case-service.{" "}
            <span className="error-detail">{connectionErrorDetail(cases.error)}</span>
          </p>
        )}
        {cases.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Titulo</th>
                <th>Prioridad</th>
                <th>Estado</th>
                <th>Asignado</th>
                <th>SLA vence</th>
                <th>Origen</th>
              </tr>
            </thead>
            <tbody>
              {cases.data.map((c) => {
                const breached = isSlaBreached(c.sla_due_at, c.status);
                return (
                  <tr key={c.id}>
                    <td>{c.title}</td>
                    <td><SeverityBadge value={c.priority} /></td>
                    <td><StatusBadge value={c.status} /></td>
                    <td>{c.assignee || "sin asignar"}</td>
                    <td className={breached ? "text-danger" : undefined}>
                      {c.sla_due_at ? new Date(c.sla_due_at).toLocaleString() : "-"}
                      {breached && " (vencido)"}
                    </td>
                    <td>{c.source}</td>
                  </tr>
                );
              })}
              {cases.data.length === 0 && (
                <tr><td colSpan={6} className="empty-hint">Sin casos abiertos todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
