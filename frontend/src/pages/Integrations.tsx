import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { integrationApi } from "../services/api";
import type { ActionLogOut, ConnectorOut, TicketLogOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

type ConnectorKind = "firewall" | "edr" | "ticketing";

const CONFIG_PLACEHOLDER: Record<ConnectorKind, string> = {
  firewall: '{\n  "base_url": "https://firewall.example/api",\n  "header_name": "X-Api-Key",\n  "api_key": "..."\n}',
  edr: '{\n  "base_url": "https://edr.example/api",\n  "header_name": "X-Api-Key",\n  "api_key": "..."\n}',
  ticketing:
    '{\n  "base_url": "https://tuempresa.atlassian.net",\n  "email": "soc@tuempresa.com",\n  "api_token": "...",\n  "project_key": "SEC",\n  "issue_type": "Task",\n  "priority_map": { "critical": "Highest", "high": "High" }\n}',
};

export default function Integrations() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ConnectorKind>("ticketing");
  const [configText, setConfigText] = useState(CONFIG_PLACEHOLDER.ticketing);
  const [configError, setConfigError] = useState("");

  const connectors = useQuery({
    queryKey: ["connectors"],
    queryFn: async () => (await integrationApi.get<ConnectorOut[]>("/connectors")).data,
  });
  const actions = useQuery({
    queryKey: ["integration-actions"],
    queryFn: async () => (await integrationApi.get<ActionLogOut[]>("/actions")).data,
  });
  const tickets = useQuery({
    queryKey: ["integration-tickets"],
    queryFn: async () => (await integrationApi.get<TicketLogOut[]>("/tickets")).data,
  });

  const createConnector = useMutation({
    mutationFn: async () => {
      let config: Record<string, unknown>;
      try {
        config = configText.trim() ? JSON.parse(configText) : {};
      } catch {
        throw new Error("La configuracion no es JSON valido");
      }
      return (await integrationApi.post<ConnectorOut>("/connectors", { name, kind, config, enabled: true })).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
      setName("");
    },
  });

  function onKindChange(next: ConnectorKind) {
    setKind(next);
    setConfigText(CONFIG_PLACEHOLDER[next]);
    setConfigError("");
  }

  function onSubmit() {
    setConfigError("");
    createConnector.mutate(undefined, {
      onError: (err) => {
        if (err instanceof Error && err.message === "La configuracion no es JSON valido") {
          setConfigError(err.message);
        }
      },
    });
  }

  return (
    <div>
      <PageHeader
        title="Integraciones"
        subtitle="Conectores de contencion (firewall/EDR) y de ticketing (ej. Jira). Por defecto en modo DRY-RUN: ninguna accion toca infraestructura real sin un conector configurado y el flag explicitamente desactivado (INTEGRATION_DRY_RUN=false)."
      />

      <div className="panel">
        <h2>Nuevo conector</h2>
        <div className="inline-form">
          <input placeholder="Nombre" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={kind} onChange={(e) => onKindChange(e.target.value as ConnectorKind)}>
            <option value="ticketing">ticketing (ej. Jira)</option>
            <option value="firewall">firewall</option>
            <option value="edr">edr</option>
          </select>
        </div>
        <textarea
          className="mono"
          style={{ width: "100%", minHeight: 140, marginTop: 8 }}
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
        />
        <div style={{ marginTop: 8 }}>
          <button className="btn-primary" onClick={onSubmit} disabled={createConnector.isPending || !name.trim()}>
            {createConnector.isPending ? "Creando..." : "Crear conector"}
          </button>
        </div>
        {configError && <p className="error-text">{configError}</p>}
        {createConnector.isError && !configError && (
          <p className="error-text">
            No se pudo crear el conector.{" "}
            <span className="error-detail">{connectionErrorDetail(createConnector.error)}</span>
          </p>
        )}
      </div>

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
                <tr><td colSpan={3} className="empty-hint">Sin conectores configurados -- toda accion de contencion/ticketing queda en modo simulado.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Tickets abiertos (ej. Jira)</h2>
        {tickets.data && (
          <table className="data-table">
            <thead>
              <tr><th>Titulo</th><th>Prioridad</th><th>Estado</th><th>Ticket externo</th><th>Fecha</th></tr>
            </thead>
            <tbody>
              {tickets.data.map((t) => (
                <tr key={t.id}>
                  <td>{t.title}</td>
                  <td>{t.priority}</td>
                  <td><StatusBadge value={t.status} /></td>
                  <td>
                    {t.external_url ? (
                      <a href={t.external_url} target="_blank" rel="noreferrer">{t.external_key || t.external_url}</a>
                    ) : (
                      t.error || "-"
                    )}
                  </td>
                  <td>{new Date(t.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {tickets.data.length === 0 && (
                <tr><td colSpan={5} className="empty-hint">Sin tickets creados todavia (se abren desde un playbook de SOAR con el paso "create_ticket").</td></tr>
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
