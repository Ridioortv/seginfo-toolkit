import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { soarApi } from "../services/api";
import type { PlaybookOut, PlaybookRunOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

const STEPS_PLACEHOLDER = `[
  { "action": "notify", "params": {} }
]`;

const STEPS_HINT =
  'Acciones disponibles: block_ip, isolate_host, create_case, create_ticket, notify. ' +
  'Cada paso es { "action": "...", "params": { ... } } -- params vacio usa los valores por defecto ' +
  '(ej. resuelve la IP/host desde la alerta, o notifica a todos los canales habilitados).';

export default function Soar() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [minSeverity, setMinSeverity] = useState("high");
  const [ruleTags, setRuleTags] = useState("");
  const [stepsText, setStepsText] = useState(STEPS_PLACEHOLDER);
  const [stepsError, setStepsError] = useState("");

  const playbooks = useQuery({
    queryKey: ["playbooks"],
    queryFn: async () => (await soarApi.get<PlaybookOut[]>("/playbooks")).data,
  });
  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: async () => (await soarApi.get<PlaybookRunOut[]>("/runs")).data,
  });

  const createPlaybook = useMutation({
    mutationFn: async () => {
      let steps: Record<string, unknown>[];
      try {
        steps = stepsText.trim() ? JSON.parse(stepsText) : [];
      } catch {
        throw new Error("Los pasos (steps) no son JSON valido");
      }
      return (
        await soarApi.post<PlaybookOut>("/playbooks", {
          name,
          description,
          min_severity: minSeverity,
          rule_tags: ruleTags.split(",").map((t) => t.trim()).filter(Boolean),
          steps,
          is_enabled: true,
        })
      ).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      setName("");
      setDescription("");
      setRuleTags("");
    },
  });

  function onSubmit() {
    setStepsError("");
    createPlaybook.mutate(undefined, {
      onError: (err) => {
        if (err instanceof Error && err.message === "Los pasos (steps) no son JSON valido") {
          setStepsError(err.message);
        }
      },
    });
  }

  return (
    <div>
      <PageHeader
        title="SOAR"
        subtitle="Playbooks de respuesta automatizada. Todas las acciones de contencion corren en modo DRY-RUN salvo que un operador lo desactive explicitamente (ver SOAR_DRY_RUN / INTEGRATION_DRY_RUN / NOTIFICATION_DRY_RUN)."
      />

      <div className="panel">
        <h2>Nuevo playbook</h2>
        <div className="inline-form">
          <input placeholder="Nombre" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            placeholder="Tags de regla (separados por coma, opcional)"
            value={ruleTags}
            onChange={(e) => setRuleTags(e.target.value)}
          />
        </div>
        <input
          placeholder="Descripcion"
          style={{ width: "100%", marginTop: 8 }}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
        <p className="empty-hint" style={{ marginTop: 8 }}>{STEPS_HINT}</p>
        <textarea
          className="mono"
          style={{ width: "100%", minHeight: 120 }}
          value={stepsText}
          onChange={(e) => setStepsText(e.target.value)}
        />
        <div style={{ marginTop: 8 }}>
          <button className="btn-primary" onClick={onSubmit} disabled={createPlaybook.isPending || !name.trim()}>
            {createPlaybook.isPending ? "Creando..." : "Crear playbook"}
          </button>
        </div>
        {stepsError && <p className="error-text">{stepsError}</p>}
        {createPlaybook.isError && !stepsError && (
          <p className="error-text">
            No se pudo crear el playbook.{" "}
            <span className="error-detail">{connectionErrorDetail(createPlaybook.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Playbooks</h2>
        {playbooks.isError && (
          <p className="error-text">
            No se pudo conectar con soar-service.{" "}
            <span className="error-detail">{connectionErrorDetail(playbooks.error)}</span>
          </p>
        )}
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
                  <td>{p.steps.map((s) => (s as { action?: string }).action).join(", ") || p.steps.length}</td>
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
