import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { integrationApi, notificationApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { ActionLogOut, ChannelOut, ConnectorOut, TicketLogOut } from "../types";
import { PROVIDER_LABEL, STATE_BADGE, STATE_LABEL, buildTicketingConfig, webhookUrl, type TicketLink } from "../utils/tickets";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";
import { currentLocale, t } from "../i18n";
import AntiEstafa from "./integrations/AntiEstafa";

type ConnectorKind = "firewall" | "edr" | "ticketing";

const KIND_LABELS: Record<ConnectorKind, string> = {
  firewall: "Firewall (bloqueo de IPs)",
  edr: "EDR / NAC (aislamiento de hosts)",
  ticketing: "Tickets (Jira o ServiceNow)",
};

type FirewallLikeForm = { baseUrl: string; headerName: string; apiKey: string };
type TicketingForm = {
  provider: "jira" | "servicenow"; baseUrl: string; email: string; username: string; apiToken: string; projectKey: string; issueType: string; table: string;
  priorityCritical: string; priorityHigh: string; priorityMedium: string; priorityLow: string;
};

const EMPTY_FIREWALL_FORM: FirewallLikeForm = { baseUrl: "", headerName: "X-Api-Key", apiKey: "" };
const EMPTY_TICKETING_FORM: TicketingForm = {
  provider: "jira", baseUrl: "", email: "", username: "", apiToken: "", projectKey: "", issueType: "Task", table: "incident",
  priorityCritical: "Highest", priorityHigh: "High", priorityMedium: "Medium", priorityLow: "Low",
};

export default function Integrations() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ConnectorKind>("ticketing");
  const [firewallForm, setFirewallForm] = useState<FirewallLikeForm>(EMPTY_FIREWALL_FORM);
  const [ticketingForm, setTicketingForm] = useState<TicketingForm>(EMPTY_TICKETING_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [notifyIds, setNotifyIds] = useState<string[]>([]);
  const [webhook, setWebhook] = useState<{ id: string; path: string } | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null);
  const role = useAuthStore((st) => st.claims?.role) ?? "";
  const isAdmin = role === "admin";
  const canSync = role === "admin" || role === "soc_manager";

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

  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: async () => (await notificationApi.get<ChannelOut[]>("/channels")).data,
  });
  const links = useQuery({
    queryKey: ["ticket-links-all"], refetchInterval: 60_000,
    queryFn: async () => (await integrationApi.get<TicketLink[]>("/ticket-links")).data,
  });
  const syncAll = useMutation({
    mutationFn: async () => (await integrationApi.post<{ checked: number; changed: number }>("/ticket-links/sync")).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["ticket-links-all"] }),
  });
  const testConnector = useMutation({
    mutationFn: async (id: string) => ({ id, ...(await integrationApi.post<{ ok: boolean; message: string }>(`/connectors/${id}/test`)).data }),
    onSuccess: (r) => setTestResult(r),
  });
  const makeSecret = useMutation({
    mutationFn: async (id: string) => ({ id, path: (await integrationApi.post<{ path: string }>(`/connectors/${id}/webhook-secret`)).data.path }),
    onSuccess: (r) => { setWebhook(r); queryClient.invalidateQueries({ queryKey: ["connectors"] }); },
  });
  const chatChannels = (channels.data ?? []).filter((c) => c.channel_type !== "generic_webhook");
  const publicBase = String(integrationApi.defaults.baseURL ?? "");
  const webhookBase = /localhost|127\.0\.0\.1/.test(publicBase) ? "https://TU-SERVIDOR:8011" : publicBase;

  function buildConfig(): Record<string, unknown> {
    if (kind === "ticketing") {
      return buildTicketingConfig({
        provider: ticketingForm.provider, baseUrl: ticketingForm.baseUrl, email: ticketingForm.email, username: ticketingForm.username,
        secret: ticketingForm.apiToken, projectKey: ticketingForm.projectKey, issueType: ticketingForm.issueType, table: ticketingForm.table,
        priorities: { critical: ticketingForm.priorityCritical, high: ticketingForm.priorityHigh, medium: ticketingForm.priorityMedium, low: ticketingForm.priorityLow },
        notifyChannelIds: notifyIds,
      });
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
      setNotifyIds([]);
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

      <AntiEstafa />

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
              <select value={ticketingForm.provider} aria-label={t("Sistema de tickets")}
                onChange={(e) => setTicketingForm((f) => ({ ...f, provider: e.target.value as "jira" | "servicenow" }))}>
                <option value="jira">Jira</option>
                <option value="servicenow">ServiceNow</option>
              </select>
              <input
                placeholder={ticketingForm.provider === "jira" ? t("URL base (ej. https://tuempresa.atlassian.net)") : t("URL base (ej. https://tuempresa.service-now.com)")}
                style={{ flex: 2 }}
                value={ticketingForm.baseUrl}
                onChange={(e) => setTicketingForm((f) => ({ ...f, baseUrl: e.target.value }))}
              />
              {ticketingForm.provider === "jira" ? (
                <input placeholder="Email de la cuenta" value={ticketingForm.email} onChange={(e) => setTicketingForm((f) => ({ ...f, email: e.target.value }))} />
              ) : (
                <input placeholder={t("Usuario de ServiceNow")} value={ticketingForm.username} onChange={(e) => setTicketingForm((f) => ({ ...f, username: e.target.value }))} />
              )}
            </div>
            <div className="inline-form" style={{ marginTop: 8 }}>
              <input
                type="password"
                placeholder={ticketingForm.provider === "jira" ? "API token" : t("Contrasena del usuario")}
                value={ticketingForm.apiToken}
                onChange={(e) => setTicketingForm((f) => ({ ...f, apiToken: e.target.value }))}
              />
              {ticketingForm.provider === "jira" ? (
                <>
                  <input placeholder="Clave del proyecto (ej. SEC)" value={ticketingForm.projectKey} onChange={(e) => setTicketingForm((f) => ({ ...f, projectKey: e.target.value }))} />
                  <input placeholder="Tipo de ticket (ej. Task)" value={ticketingForm.issueType} onChange={(e) => setTicketingForm((f) => ({ ...f, issueType: e.target.value }))} />
                </>
              ) : (
                <input placeholder={t("Tabla (por defecto incident)")} value={ticketingForm.table} onChange={(e) => setTicketingForm((f) => ({ ...f, table: e.target.value }))} />
              )}
            </div>
            {ticketingForm.provider === "jira" && (
              <>
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
            )}
            {chatChannels.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <span className="empty-hint">{t("Avisar por chat cuando se crea o se resuelve un ticket (opcional):")}</span>
                {chatChannels.map((c) => (
                  <label key={c.id} className="gov-row-check" style={{ marginLeft: 12 }}>
                    <input type="checkbox" checked={notifyIds.includes(c.id)}
                      onChange={(e) => setNotifyIds((ids) => (e.target.checked ? [...ids, c.id] : ids.filter((i) => i !== c.id)))} /> {c.name}
                  </label>
                ))}
              </div>
            )}
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
                    {c.kind === "ticketing" && isAdmin && (
                      <>
                        <button className="btn-link" disabled={testConnector.isPending} onClick={() => testConnector.mutate(c.id)}>{t("Probar conexion")}</button>{" "}
                        <button className="btn-link" disabled={makeSecret.isPending} onClick={() => makeSecret.mutate(c.id)}>
                          {c.config.webhook_enabled ? t("Nuevo secreto de webhook") : t("Activar webhook de vuelta")}
                        </button>{" "}
                      </>
                    )}
                    <button className="btn-link" onClick={() => deleteConnector.mutate(c.id)}>Eliminar</button>
                    {testResult?.id === c.id && <div className={testResult.ok ? "empty-hint" : "error-text"}>{testResult.message}</div>}
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
        {(testConnector.isError || makeSecret.isError) && (
          <p className="error-text"><span className="error-detail">{connectionErrorDetail(testConnector.error ?? makeSecret.error)}</span></p>
        )}
        {webhook && (
          <div className="gov-callout gov-warn">
            <div>
              <strong>{t("Webhook de vuelta (se muestra una sola vez)")}</strong>
              <p>{t("En Jira (Configuracion > Sistema > Webhooks, evento \"issue updated\") o en ServiceNow (una Business Rule con REST Message), apunta el aviso a esta direccion. Tiene que ser accesible desde internet por HTTPS; cambia TU-SERVIDOR por la direccion publica de tu instalacion.")}</p>
              <input readOnly style={{ width: "100%" }} value={webhookUrl(webhookBase, webhook.path)} onFocus={(e) => e.target.select()} aria-label={t("Direccion del webhook")} />
              <p className="empty-hint">{t("TERO no se fia del contenido del aviso: solo lo usa para saber que ticket cambio y vuelve a preguntarle el estado a tu sistema de tickets. Si no podes exponer el webhook, TERO consulta solo cada 5 minutos.")}</p>
              <button className="btn-link" onClick={() => setWebhook(null)}>{t("Ocultar")}</button>
            </div>
          </div>
        )}
      </div>

      <div className="panel">
        <h2>{t("Tickets vinculados a vulnerabilidades y casos")}</h2>
        <p className="empty-hint">{t("Se abren desde el detalle de una vulnerabilidad o de un caso. Cuando el ticket se resuelve en tu sistema, TERO marca la vulnerabilidad como remediada y la verifica con un nuevo escaneo.")}</p>
        {canSync && (
          <button className="btn-secondary" disabled={syncAll.isPending} onClick={() => syncAll.mutate()}>{syncAll.isPending ? t("Consultando...") : t("Consultar ahora")}</button>
        )}
        {syncAll.isSuccess && <p className="empty-hint">{t("Se consultaron {0} tickets; {1} cambiaron.", syncAll.data.checked, syncAll.data.changed)}</p>}
        {syncAll.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(syncAll.error)}</span></p>}
        {links.data && (
          <table className="data-table">
            <thead><tr><th>{t("Ticket")}</th><th>{t("Sistema")}</th><th>{t("Vinculado a")}</th><th>{t("Estado")}</th><th>{t("Detalle")}</th></tr></thead>
            <tbody>
              {links.data.map((l) => (
                <tr key={l.id}>
                  <td>{l.external_url ? <a href={l.external_url} target="_blank" rel="noreferrer">{l.external_key}</a> : l.external_key || "-"}</td>
                  <td>{PROVIDER_LABEL[l.provider] ?? l.provider}</td>
                  <td>{l.subject_type === "vulnerability" ? t("Vulnerabilidad") : t("Caso")}: {l.subject_title}</td>
                  <td><span className={STATE_BADGE[l.state]}>{t(STATE_LABEL[l.state])}</span></td>
                  <td>{l.last_error ? <span className="error-text">{l.last_error}</span> : l.applied_note || (l.external_status ? l.external_status : "-")}</td>
                </tr>
              ))}
              {links.data.length === 0 && <tr><td colSpan={5} className="empty-hint">{t("Todavia no hay tickets vinculados.")}</td></tr>}
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
                  <td>{new Date(t.created_at).toLocaleString(currentLocale())}</td>
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
                  <td>{new Date(a.created_at).toLocaleString(currentLocale())}</td>
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
