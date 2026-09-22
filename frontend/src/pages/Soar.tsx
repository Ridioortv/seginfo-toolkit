import { useQuery } from "@tanstack/react-query";
import { soarApi } from "../services/api";
import type { PlaybookOut, PlaybookRunOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";

export default function Soar() {
  const playbooks = useQuery({
    queryKey: ["playbooks"],
    queryFn: async () => (await soarApi.get<PlaybookOut[]>("/playbooks")).data,
  });
  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: async () => (await soarApi.get<PlaybookRunOut[]>("/runs")).data,
  });

  return (
    <div>
      <PageHeader
        title="SOAR"
        subtitle="Playbooks de respuesta automatizada. Todas las acciones de contencion corren en modo DRY-RUN salvo que un operador lo desactive explicitamente (ver SOAR_DRY_RUN / INTEGRATION_DRY_RUN)."
      />

      <div className="panel">
        <h2>Playbooks</h2>
        {playbooks.isError && <p className="error-text">No se pudo conectar con soar-service.</p>}
        {playbooks.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Severidad minima</th>
                <th>Tags de regla</th>
                <th>Pasos</th>
                <th>Habilitado</th>
              </tr>
            </thead>
            <tbody>
              {playbooks.data.map((p) => (
                <tr key={p.id}>
                  <td>{p.name}</td>
                  <td>{p.min_severity}</td>
                  <td className="mono">{p.rule_tags.join(", ")}</td>
                  <td>{p.steps.length}</td>
                  <td>{p.is_enabled ? "si" : "no"}</td>
                </tr>
              ))}
              {playbooks.data.length === 0 && (
                <tr><td colSpan={5} className="empty-hint">Sin playbooks cargados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Ejecuciones</h2>
        {runs.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Playbook</th>
                <th>Estado</th>
                <th>Disparado por</th>
                <th>Creada</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.playbook_name}</td>
                  <td><StatusBadge value={r.status} /></td>
                  <td>{r.triggered_by}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {runs.data.length === 0 && (
                <tr><td colSpan={4} className="empty-hint">Sin ejecuciones todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
