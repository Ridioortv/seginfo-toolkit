import { useQuery } from "@tanstack/react-query";
import { scanApi } from "../services/api";
import type { ScanJobOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";

export default function Scans() {
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: async () => (await scanApi.get<ScanJobOut[]>("/scans")).data,
  });

  return (
    <div>
      <PageHeader
        title="Escaneos"
        subtitle="Orquestacion de escaneres defensivos (Nmap/Trivy/Nuclei/OpenVAS) -- deteccion, nunca explotacion"
      />
      <div className="panel">
        {scans.isLoading && <p className="empty-hint">Cargando...</p>}
        {scans.isError && <p className="error-text">No se pudo conectar con scan-service.</p>}
        {scans.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Target</th>
                <th>Estado</th>
                <th>Hallazgos</th>
                <th>Creado</th>
              </tr>
            </thead>
            <tbody>
              {scans.data.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td>{s.scanner_type}</td>
                  <td className="mono">{s.target}</td>
                  <td><StatusBadge value={s.status} /></td>
                  <td>{s.findings.length}</td>
                  <td>{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {scans.data.length === 0 && (
                <tr><td colSpan={6} className="empty-hint">Sin escaneos ejecutados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
