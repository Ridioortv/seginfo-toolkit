import { useQuery } from "@tanstack/react-query";
import { assetApi } from "../services/api";
import type { AssetOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge } from "../components/Badge";

export default function Assets() {
  const assets = useQuery({
    queryKey: ["assets"],
    queryFn: async () => (await assetApi.get<AssetOut[]>("/assets")).data,
  });

  return (
    <div>
      <PageHeader title="Activos" subtitle="Inventario de activos monitoreados por la plataforma" />
      <div className="panel">
        {assets.isLoading && <p className="empty-hint">Cargando...</p>}
        {assets.isError && <p className="error-text">No se pudo conectar con asset-service.</p>}
        {assets.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP</th>
                <th>SO</th>
                <th>Entorno</th>
                <th>Criticidad</th>
                <th>Owner</th>
                <th>Activo</th>
              </tr>
            </thead>
            <tbody>
              {assets.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.hostname}</td>
                  <td className="mono">{a.ip_address}</td>
                  <td>{a.os_name} {a.os_version}</td>
                  <td>{a.environment}</td>
                  <td><SeverityBadge value={a.criticality} /></td>
                  <td>{a.owner}</td>
                  <td>{a.is_active ? "si" : "no"}</td>
                </tr>
              ))}
              {assets.data.length === 0 && (
                <tr><td colSpan={7} className="empty-hint">Sin activos registrados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
