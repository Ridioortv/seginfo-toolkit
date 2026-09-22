import { useQuery } from "@tanstack/react-query";
import { integrationApi } from "../services/api";
import type { ActionLogOut, ConnectorOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";

export default function Integrations() {
  const connectors = useQuery({
    queryKey: ["connectors"],
    queryFn: async () => (await integrationApi.get<ConnectorOut[]>("/connectors")).data,
  });
  const actions = useQuery({
    queryKey: ["integration-actions"],
    queryFn: async () => (await integrationApi.get<ActionLogOut[]>("/actions")).data,
  });

  return (
    <div>
      <PageHeader
        title="Integraciones"
        subtitle="Conectores genericos de contencion (firewall/EDR). Por defecto en modo DRY-RUN: ninguna accion toca infraestructura real sin un conector configurado y el flag explicitamente desactivado."
      />

      <div className="panel">
        <h2>Conectores</h2>
        {connectors.data && (
          <table className="data-table">
            <thead>
              <tr><th>Nombre</th><th>Tipo</th><th>Habilitado</th></tr>
            </thead>
            <tbody>
              {connectors.data.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.kind}</td>
                  <td>{c.enabled ? "si" : "no"}</td>
                </tr>
              ))}
              {connectors.data.length === 0 && (
                <tr><td colSpan={3} className="empty-hint">Sin conectores configurados -- toda accion de contencion queda en modo simulado.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Historial de acciones de contencion</h2>
        {actions.data && (
          <table className="data-table">
            <thead>
              <tr><th>Accion</th><th>Objetivo</th><th>Estado</th><th>Error</th><th>Fecha</th></tr>
            </thead>
            <tbody>
              {actions.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.action}</td>
                  <td className="mono">{a.target}</td>
                  <td><StatusBadge value={a.status} /></td>
                  <td>{a.error || "-"}</td>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {actions.data.length === 0 && (
                <tr><td colSpan={5} className="empty-hint">Sin acciones de contencion registradas todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
