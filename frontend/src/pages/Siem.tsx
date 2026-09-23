import { useQuery } from "@tanstack/react-query";
import { siemApi } from "../services/api";
import type { AlertOut, SigmaRuleOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

export default function Siem() {
  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: async () => (await siemApi.get<AlertOut[]>("/alerts")).data,
  });
  const rules = useQuery({
    queryKey: ["rules"],
    queryFn: async () => (await siemApi.get<SigmaRuleOut[]>("/rules")).data,
  });

  return (
    <div>
      <PageHeader title="SIEM" subtitle="Alertas generadas por el motor de reglas Sigma sobre logs normalizados (ECS-lite)" />

      <div className="panel">
        <h2>Alertas</h2>
        {alerts.isLoading && <p className="empty-hint">Cargando...</p>}
        {alerts.isError && (
          <p className="error-text">
            No se pudo conectar con siem-service.{" "}
            <span className="error-detail">{connectionErrorDetail(alerts.error)}</span>
          </p>
        )}
        {alerts.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Regla</th>
                <th>Severidad</th>
                <th>Estado</th>
                <th>SOAR disparado</th>
                <th>Creada</th>
              </tr>
            </thead>
            <tbody>
              {alerts.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.rule_name}</td>
                  <td><SeverityBadge value={a.severity} /></td>
                  <td><StatusBadge value={a.status} /></td>
                  <td>{a.soar_triggered ? "si" : "no"}</td>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {alerts.data.length === 0 && (
                <tr><td colSpan={5} className="empty-hint">Sin alertas todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Reglas de deteccion (Sigma)</h2>
        {rules.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Severidad</th>
                <th>Tags</th>
                <th>Habilitada</th>
              </tr>
            </thead>
            <tbody>
              {rules.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td><SeverityBadge value={r.severity} /></td>
                  <td className="mono">{r.tags.join(", ")}</td>
                  <td>{r.is_enabled ? "si" : "no"}</td>
                </tr>
              ))}
              {rules.data.length === 0 && (
                <tr><td colSpan={4} className="empty-hint">Sin reglas cargadas todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
