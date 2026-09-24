import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { purpleApi } from "../services/api";
import type { CoverageResult, ExerciseOut, TechniqueOut } from "../types";
import PageHeader from "../components/PageHeader";
import { connectionErrorDetail } from "../utils/errors";

function groupByTactic(techniques: TechniqueOut[]): Record<string, TechniqueOut[]> {
  const groups: Record<string, TechniqueOut[]> = {};
  for (const t of techniques) {
    (groups[t.tactic] ??= []).push(t);
  }
  return groups;
}

export default function PurpleTeam() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [formError, setFormError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

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

  const createExercise = useMutation({
    mutationFn: async () =>
      (
        await purpleApi.post<ExerciseOut>("/exercises", {
          name,
          description,
          declared_technique_ids: Array.from(selectedIds),
        })
      ).data,
    onSuccess: () => {
      setName("");
      setDescription("");
      setSelectedIds(new Set());
      setFormError(null);
      queryClient.invalidateQueries({ queryKey: ["exercises"] });
    },
  });

  const recomputeCoverage = useMutation({
    mutationFn: async (exerciseId: string) =>
      (await purpleApi.post<CoverageResult>(`/exercises/${exerciseId}/coverage`)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["exercises"] }),
  });

  function toggleTechnique(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function onCreateExercise() {
    setFormError(null);
    if (!name.trim()) {
      setFormError("Ingresa un nombre para el ejercicio.");
      return;
    }
    if (selectedIds.size === 0) {
      setFormError("Marca al menos una tecnica declarada como probada.");
      return;
    }
    createExercise.mutate();
  }

  const groups = groupByTactic(techniques.data ?? []);

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
        <div className="stat-card">
          <span className="stat-label">Ejercicios declarados</span>
          <span className="stat-value">{exercises.data?.length ?? "-"}</span>
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
        <h2>Declarar un nuevo ejercicio</h2>
        <p className="empty-hint">
          Marca las tecnicas ATT&CK que un ejercicio (interno o de un proveedor externo) declaro haber puesto a
          prueba -- esta plataforma nunca ejecuta nada, solo analiza si hay una regla de SIEM que las detectaria.
        </p>
        <div className="inline-form">
          <input placeholder="Nombre del ejercicio" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <input
          placeholder="Descripcion (opcional)"
          style={{ width: "100%", marginTop: 8 }}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />

        <div style={{ marginTop: 10 }}>
          {Object.entries(groups).map(([tactic, techs]) => (
            <div key={tactic} style={{ marginBottom: 8 }}>
              <strong>{tactic}</strong>
              <div>
                {techs.map((t) => (
                  <label key={t.technique_id} style={{ display: "inline-flex", alignItems: "center", gap: 4, marginRight: 14 }}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(t.technique_id)}
                      onChange={() => toggleTechnique(t.technique_id)}
                    />
                    {t.technique_id} - {t.name}
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 10 }}>
          <button className="btn-primary" onClick={onCreateExercise} disabled={createExercise.isPending}>
            {createExercise.isPending ? "Creando..." : "Crear ejercicio"}
          </button>
        </div>
        {formError && <p className="error-text">{formError}</p>}
        {createExercise.isError && !formError && (
          <p className="error-text">
            No se pudo crear el ejercicio.{" "}
            <span className="error-detail">{connectionErrorDetail(createExercise.error)}</span>
          </p>
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
                <th>Cobertura</th>
                <th>Creado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {exercises.data.map((e) => {
                const last = e.last_coverage_result as unknown as CoverageResult | undefined;
                return (
                  <Fragment key={e.id}>
                    <tr>
                      <td>{e.name}</td>
                      <td className="mono">{e.declared_technique_ids.join(", ")}</td>
                      <td>{last?.coverage_pct !== undefined ? `${last.coverage_pct}%` : "sin calcular"}</td>
                      <td>{new Date(e.created_at).toLocaleString()}</td>
                      <td>
                        <button
                          className="btn-link"
                          onClick={() => recomputeCoverage.mutate(e.id)}
                          disabled={recomputeCoverage.isPending}
                        >
                          Recalcular cobertura
                        </button>
                        {" / "}
                        <button className="btn-link" onClick={() => setExpandedId(expandedId === e.id ? null : e.id)}>
                          {expandedId === e.id ? "Ocultar" : "Ver gaps"}
                        </button>
                      </td>
                    </tr>
                    {expandedId === e.id && (
                      <tr>
                        <td colSpan={5} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
                          {last?.gaps && last.gaps.length > 0 ? (
                            <>
                              <strong>Tecnicas declaradas sin regla de deteccion:</strong>
                              <ul>
                                {last.gaps.map((g) => (
                                  <li key={g.technique_id}>{g.technique_id} - {g.name} ({g.tactic})</li>
                                ))}
                              </ul>
                            </>
                          ) : (
                            <p className="empty-hint">
                              {last ? "Sin gaps -- todas las tecnicas declaradas tienen al menos una regla que las detecta." : "Todavia no se calculo la cobertura de este ejercicio."}
                            </p>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin ejercicios purple team declarados todavia -- declara uno arriba.</p>
        )}
      </div>
    </div>
  );
}
