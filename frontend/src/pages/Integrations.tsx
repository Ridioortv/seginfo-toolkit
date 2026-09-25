import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { integrationApi } from "../services/api";
import type { ActionLogOut, ConnectorOut, TicketLogOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

type ConnectorKind = "firewall" | "edr" | "ticketing";

const KIND_LABELS: Record<ConnectorKind, string> = {
  firewall: "Firewall (bloqueo de IPs)",
  edr: "EDR / NAC (aislamiento de hosts)",
  ticketing: "Ticketing (ej. Jira)",
};

type FirewallLikeForm = { baseUrl: string; headerName: string; apiKey: string };
type TicketingForm = {
  baseUrl: string; email: string; apiToken: string; projectKey: string; issueType: string;
  priorityCritical: string; priorityHigh: string; priorityMedium: string; priorityLow: string;
};

const EMPTY_FIREWALL_FORM: FirewallLikeForm = { baseUrl: "", headerName: "X-Api-Key", apiKey: "" };
const EMPTY_TICKETING_FORM: TicketingForm = {
  baseUrl: "", email: "", apiToken: "", projectKey: "", issueType: "Task",
  priorityCritical: "Highest", priorityHigh: "High", priorityMedium: "Medium", priorityLow: "Low",
};

export default function Integrations() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ConnectorKind>("ticketing");
  const [firewallForm, setFirewallForm] = useState<FirewallLikeForm>(EMPTY_FIREWALL_FORM);
  const [ticketingForm, setTicketingForm] = useState<TicketingForm>(EMPTY_TICKETING_FORM);
  const [formError, setFormError] = useState<string | null>(null);

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

  function buildConfig(): Record<string, unknown> {
    if (kind === "ticketing") {
      const priorityMap: Record<string, string> = {};
      if (ticketingForm.priorityCritical) priorityMap.critical = ticketingForm.priorityCritical;
      if (ticketingForm.priorityHigh) priorityMap.high = ticketingForm.priorityHigh;
      if (ticketingForm.priorityMedium) priorityMap.medium = ticketingForm.priorityMedium;
      if (ticketingForm.priorityLow) priorityMap.low = ticketingForm.priorityLow;
      return {
        base_url: ticketingForm.baseUrl,
        email: ticketingForm.email,
        api_token: ticketingForm.apiToken,
        project_key: ticketingForm.projectKey,
        issue_type: ticketingForm.issueType || "Task",
        priority_map: priorityMap,
      };
    }
    return {
      base_url: firewallForm.baseUrl,
      header_name: firewallForm.headerName || "X-Api-Key",
      api_key: firewallForm.apiKey,
    };
  }

  const createConnector = useMutation({
    mutationFn: async () =>
      (await integrationApi.post<ConnectorOut>("/connectors", { name, kind, config: buildConfig(), enabled: true })).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
      setName("");
      setFirewallForm(EMPTY_FIREWALL_FORM);
      setTicketingForm(EMPTY_TICKETING_FORM);
      setFormError(null);
    },
  });

  const toggleConnector = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      (await integrationApi.patch<ConnectorOut>(`/connectors/${id}`, { enabled })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["connectors"] }),
  });

  const deleteConnector = useMutation({
    mutationFn: async (id: string) => integrationApi.delete(`/connectors/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["connectors"] }),
  });

  function onSubmit() {
    setFormError(null);
    if (!name.trim()) {
      setFormError("Ingresa un nombre para el conector.");
      return;
    }
    const baseUrl = kind === "ticketing" ? ticketingForm.baseUrl : firewallForm.baseUrl;
    if (!baseUrl.trim()) {
      setFormError("Ingresa la URL base del sistema al que te vas a conectar.");
      return;
    }
    createConnector.mutate();
  }

  return (
    <div>
      <PageHeader
        title="Integraciones"
        subtitle="Conectores de contencion (firewall/EDR) y de ticketing (ej. Jira). Por defecto en modo DRY-RUN: ninguna accion toca infraestructura real sin un conector configurado y el flag explicitamente desactivado."
      />

      <div className="panel">
        <h2>Nuevo conector</h2>
        <div className="inline-form">
          <input placeholder="Nombre" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={kind} onChange={(e) => setKind(e.target.value as ConnectorKind)}>
            {(Object.entries(KIND_LABELS) as [ConnectorKind, string][]).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </div>

        {kind === "ticketing" ? (
          <>
            <div className="inline-form" style={{ marginTop: 8 }}>
              <input
                placeholder="URL base (ej. https://tuempresa.atlassian.net)"
                style={{ flex: 2 }}
                value={ticketingForm.baseUrl}
                onChange={(e) => setTicketingForm((f) => ({ ...f, baseUrl: e.target.value }))}
              />
              <input
                placeholder="Email de la cuenta"
                value={ticketingForm.email}
                onChange={(e) => setTicketingForm((f) => ({ ...f, email: e.target.value }))}
              />
            </div>
            <div className="inline-form" style={{ marginTop: 8 }}>
              <input
                type="password"
                placeholder="API token"
                value={ticketingForm.apiToken}
                onChange={(e) => setTicketingForm((f) => ({ ...f, apiToken: e.target.value }))}
              />
              <input
                placeholder="Clave del proyecto (ej. SEC)"
                value={ticketingForm.projectKey}
                onChange={(e) => setTicketingForm((f) => ({ ...f, projectKey: e.target.value }))}
              />
              <input
                placeholder="Tipo de ticket (ej. Task)"
                value={ticketingForm.issueType}
                onChange={(e) => setTicketingForm((f) => ({ ...f, issueType: e.target.value }))}
              />
            </div>
            <p className="empty-hint" style={{ marginTop: 8 }}>
              Mapeo de prioridad (severidad de la alerta -&gt; prioridad del ticket, opcional -- ya viene con valores
              tipicos de Jira):
            </p>
            <div className="inline-form">
              <input placeholder="Critica" value={ticketingForm.priorityCritical} onChange={(e) => setTicketingForm((f) => ({ ...f, priorityCritical: e.target.value }))} />
              <input placeholder="Alta" value={ticketingForm.priorityHigh} onChange={(e) => setTicketingForm((f) => ({ ...f, priorityHigh: e.target.value }))} />
              <input placeholder="Media" value={ticketingForm.priorityMedium} onChange={(e) => setTicketingForm((f) => ({ ...f, priorityMedium: e.target.value }))} />
              <input placeholder="Baja" value={ticketingForm.priorityLow} onChange={(e) => setTicketingForm((f) => ({ ...f, priorityLow: e.target.value }))} />
            </div>
          </>
        ) : (
          <div className="inline-form" style={{ marginTop: 8 }}>
            <input
              placeholder="URL base (ej. https://firewall.tuempresa.com/api)"
              style={{ flex: 2 }}
              value={firewallForm.baseUrl}
              onChange={(e) => setFirewallForm((f) => ({ ...f, baseUrl: e.target.value }))}
            />
            <input
              placeholder="Nombre del header de autenticacion (ej. X-Api-Key)"
              value={firewallForm.headerName}
              onChange={(e) => setFirewallForm((f) => ({ ...f, headerName: e.target.value }))}
            />
            <input
              type="password"
              placeholder="API key"
              value={firewallForm.apiKey}
              onChange={(e) => setFirewallForm((f) => ({ ...f, apiKey: e.target.value }))}
            />
          </div>
        )}

        <div style={{ marginTop: 10 }}>
          <button className="btn-primary" onClick={onSubmit} disabled={createConnector.isPending}>
            {createConnector.isPending ? "Creando..." : "Crear conector"}
          </button>
        </div>
        {formError && <p className="error-text">{formError}</p>}
        {createConnector.isError && !formError && (
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
              <tr><th>Nombre</th><th>Tipo</th><th>Habilitado</th><th></th></tr>
            </thead>
            <tbody>
              {connectors.data.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{KIND_LABELS[c.kind as ConnectorKind] ?? c.kind}</td>
                  <td>
                    <input
                      type="checkbox"
                      checked={c.enabled}
                      onChange={(e) => toggleConnector.mutate({ id: c.id, enabled: e.target.checked })}
                    />
                  </td>
                  <td>
                    <button className="btn-link" onClick={() => deleteConnector.mutate(c.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
              {connectors.data.length === 0 && (
                <tr><td colSpan={4} className="empty-hint">Sin conectores configurados -- toda accion de contencion/ticketing queda en modo simulado.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {toggleConnector.isError && (
          <p className="error-text">
            No se pudo actualizar el conector.{" "}
            <span className="error-detail">{connectionErrorDetail(toggleConnector.error)}</span>
          </p>
        )}
        {deleteConnector.isError && (
          <p className="error-text">
            No se pudo eliminar el conector.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteConnector.error)}</span>
          </p>
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
