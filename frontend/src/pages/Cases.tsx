import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { caseApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { CaseOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";
import { isSlaBreached } from "../utils/sla";

const CAN_SYNC = ["admin", "soc_manager"];

const STATUS_TRANSITIONS: Record<string, { next: string; label: string }[]> = {
  open: [{ next: "in_progress", label: "Tomar caso" }],
  in_progress: [{ next: "resolved", label: "Marcar resuelto" }, { next: "open", label: "Devolver a abierto" }],
  resolved: [{ next: "closed", label: "Cerrar" }, { next: "in_progress", label: "Reabrir" }],
  closed: [{ next: "open", label: "Reabrir" }],
};

export default function Cases() {
  const queryClient = useQueryClient();
  const claims = useAuthStore((s) => s.claims);
  const canSync = !!claims?.role && CAN_SYNC.includes(claims.role);

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [assigneeDraft, setAssigneeDraft] = useState<Record<string, string>>({});
  const [noteDraft, setNoteDraft] = useState<Record<string, string>>({});
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  const cases = useQuery({
    queryKey: ["cases"],
    queryFn: async () => (await caseApi.get<CaseOut[]>("/cases")).data,
  });

  const syncSoar = useMutation({
    mutationFn: async () => (await caseApi.post<{ imported: number; skipped: number }>("/import/soar-pending")).data,
    onSuccess: (result) => {
      setSyncFeedback(`${result.imported} caso(s) importado(s), ${result.skipped} ya existian.`);
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
    onError: (err: unknown) => {
      setSyncFeedback(err instanceof Error ? err.message : "No se pudo sincronizar con SOAR.");
    },
  });

  const updateCase = useMutation({
    mutationFn: async ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      (await caseApi.patch<CaseOut>(`/cases/${id}`, payload)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cases"] }),
  });

  const addNote = useMutation({
    mutationFn: async ({ id, notes }: { id: string; notes: string }) =>
      (await caseApi.post<CaseOut>(`/cases/${id}/timeline`, { action: "note", notes })).data,
    onSuccess: (_data, vars) => {
      setNoteDraft((prev) => ({ ...prev, [vars.id]: "" }));
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  const total = cases.data?.length ?? 0;
  const openCount = (cases.data ?? []).filter((c) => c.status === "open" || c.status === "in_progress").length;
  const breachedCount = (cases.data ?? []).filter((c) => isSlaBreached(c.sla_due_at, c.status)).length;
  const resolvedCount = (cases.data ?? []).filter((c) => c.status === "resolved" || c.status === "closed").length;

  return (
    <div>
      <PageHeader title="Casos" subtitle="Gestion de incidentes estilo ITSM con SLA por prioridad y timeline de auditoria -- se sincroniza solo con SOAR cada par de minutos" />

      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Total</span>
          <span className="stat-value">{total}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Abiertos</span>
          <span className="stat-value">{openCount}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">SLA vencido</span>
          <span className="stat-value">{breachedCount}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Resueltos/cerrados</span>
          <span className="stat-value">{resolvedCount}</span>
        </div>
      </div>

      {canSync && (
        <div className="panel">
          <div className="inline-form">
            <button className="btn-secondary" onClick={() => syncSoar.mutate()} disabled={syncSoar.isPending}>
              {syncSoar.isPending ? "Sincronizando..." : "Sincronizar con SOAR ahora"}
            </button>
            <span className="empty-hint">
              Esto ya corre solo cada par de minutos; usa este boton solo si necesitas traer un caso nuevo de inmediato.
            </span>
          </div>
          {syncFeedback && <p className="empty-hint">{syncFeedback}</p>}
        </div>
      )}

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
                <th></th>
              </tr>
            </thead>
            <tbody>
              {cases.data.map((c) => {
                const breached = isSlaBreached(c.sla_due_at, c.status);
                const transitions = STATUS_TRANSITIONS[c.status] ?? [];
                return (
                  <Fragment key={c.id}>
                    <tr>
                      <td>{c.title}</td>
                      <td><SeverityBadge value={c.priority} /></td>
                      <td><StatusBadge value={c.status} /></td>
                      <td>{c.assignee || "sin asignar"}</td>
                      <td className={breached ? "text-danger" : undefined}>
                        {c.sla_due_at ? new Date(c.sla_due_at).toLocaleString() : "-"}
                        {breached && " (vencido)"}
                      </td>
                      <td>{c.source}</td>
                      <td>
                        <button className="btn-link" onClick={() => setExpandedId(expandedId === c.id ? null : c.id)}>
                          {expandedId === c.id ? "Ocultar" : "Gestionar"}
                        </button>
                      </td>
                    </tr>
                    {expandedId === c.id && (
                      <tr>
                        <td colSpan={7} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
                          {c.description && <p>{c.description}</p>}

                          <div className="inline-form">
                            {transitions.map((t) => (
                              <button
                                key={t.next}
                                className="btn-secondary"
                                disabled={updateCase.isPending}
                                onClick={() => updateCase.mutate({ id: c.id, payload: { status: t.next } })}
                              >
                                {t.label}
                              </button>
                            ))}
                          </div>

                          <div className="inline-form" style={{ marginTop: 8 }}>
                            <input
                              placeholder="Asignar a..."
                              value={assigneeDraft[c.id] ?? c.assignee}
                              onChange={(e) => setAssigneeDraft((prev) => ({ ...prev, [c.id]: e.target.value }))}
                            />
                            <button
                              className="btn-secondary"
                              disabled={updateCase.isPending}
                              onClick={() => updateCase.mutate({ id: c.id, payload: { assignee: assigneeDraft[c.id] ?? c.assignee } })}
                            >
                              Asignar
                            </button>
                          </div>

                          <div style={{ marginTop: 10 }}>
                            <strong>Timeline:</strong>
                            <ul>
                              {c.timeline.map((t) => (
                                <li key={t.id}>
                                  {new Date(t.created_at).toLocaleString()} -- {t.action}
                                  {t.notes && `: ${t.notes}`} {t.actor && `(${t.actor})`}
                                </li>
                              ))}
                              {c.timeline.length === 0 && <li className="empty-hint">Sin eventos todavia.</li>}
                            </ul>
                            <div className="inline-form">
                              <input
                                placeholder="Agregar nota..."
                                value={noteDraft[c.id] ?? ""}
                                onChange={(e) => setNoteDraft((prev) => ({ ...prev, [c.id]: e.target.value }))}
                              />
                              <button
                                className="btn-secondary"
                                disabled={addNote.isPending || !(noteDraft[c.id] ?? "").trim()}
                                onClick={() => addNote.mutate({ id: c.id, notes: noteDraft[c.id] ?? "" })}
                              >
                                Agregar nota
                              </button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
              {cases.data.length === 0 && (
                <tr><td colSpan={7} className="empty-hint">Sin casos abiertos todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
