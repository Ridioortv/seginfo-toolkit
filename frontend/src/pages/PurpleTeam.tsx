import { useQuery } from "@tanstack/react-query";
import { purpleApi } from "../services/api";
import type { CoverageResult, ExerciseOut, TechniqueOut } from "../types";
import PageHeader from "../components/PageHeader";

export default function PurpleTeam() {
  const coverage = useQuery({
    queryKey: ["coverage-overall", "page"],
    queryFn: async () => (await purpleApi.get<CoverageResult>("/coverage/overall")).data,
  });
  const exercises = useQuery({
    queryKey: ["exercises"],
    queryFn: async () => (await purpleApi.get<ExerciseOut[]>("/exercises")).data,
  });
  const techniques = useQuery({
    queryKey: ["techniques"],
    queryFn: async () => (await purpleApi.get<TechniqueOut[]>("/techniques")).data,
  });

  return (
    <div>
      <PageHeader
        title="Purple Team"
        subtitle="Gap analysis de cobertura de deteccion MITRE ATT&CK -- solo analiza datos declarados, nunca ejecuta tecnicas"
      />

      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Cobertura global</span>
          <span className="stat-value">{coverage.data ? `${coverage.data.coverage_pct}%` : "-"}</span>
          <span className="stat-hint">{coverage.data?.covered_count ?? 0} / {coverage.data?.total_techniques ?? techniques.data?.length ?? 0} tecnicas</span>
        </div>
      </div>

      <div className="panel">
        <h2>Catalogo de tecnicas de referencia</h2>
        {coverage.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Tecnica</th>
                <th>Tactica</th>
                <th>Cobertura</th>
                <th>Reglas que la detectan</th>
              </tr>
            </thead>
            <tbody>
              {coverage.data.techniques.map((t) => (
                <tr key={t.technique_id}>
                  <td className="mono">{t.technique_id}</td>
                  <td>{t.name}</td>
                  <td>{t.tactic}</td>
                  <td>{t.covered ? "cubierta" : "sin cobertura"}</td>
                  <td className="mono">{t.matching_rules.join(", ") || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Ejercicios declarados</h2>
        {exercises.data && exercises.data.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tecnicas declaradas</th>
                <th>Creado</th>
              </tr>
            </thead>
            <tbody>
              {exercises.data.map((e) => (
                <tr key={e.id}>
                  <td>{e.name}</td>
                  <td className="mono">{e.declared_technique_ids.join(", ")}</td>
                  <td>{new Date(e.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin ejercicios purple team declarados todavia (se crean via POST /exercises).</p>
        )}
      </div>
    </div>
  );
}
