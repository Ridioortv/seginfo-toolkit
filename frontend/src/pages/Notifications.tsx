import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { notificationApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { ChannelOut, NotifyLogOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";

type ChannelType = "email" | "slack_webhook" | "generic_webhook";

const CAN_MANAGE_CHANNELS = ["admin", "soc_manager"];

export default function Notifications() {
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [sendFeedback, setSendFeedback] = useState<NotifyLogOut[] | null>(null);

  const [newName, setNewName] = useState("");
  const [newType, setNewType] = useState<ChannelType>("slack_webhook");
  const [newTarget, setNewTarget] = useState(""); // webhook_url o smtp_to segun newType
  const [newChannelError, setNewChannelError] = useState<string | null>(null);

  const claims = useAuthStore((s) => s.claims);
  const canManageChannels = !!claims?.role && CAN_MANAGE_CHANNELS.includes(claims.role);

  const queryClient = useQueryClient();

  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: async () => (await notificationApi.get<ChannelOut[]>("/channels")).data,
  });
  const logs = useQuery({
    queryKey: ["notification-logs"],
    queryFn: async () => (await notificationApi.get<NotifyLogOut[]>("/logs")).data,
  });

  const enabledChannelsCount = channels.data?.filter((c) => c.enabled).length ?? 0;

  const createChannel = useMutation({
    mutationFn: async () => {
      const config = newType === "email" ? { smtp_to: newTarget } : { webhook_url: newTarget };
      return (await notificationApi.post<ChannelOut>("/channels", {
        name: newName,
        channel_type: newType,
        config,
        enabled: true,
      })).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["channels"] });
      setNewName("");
      setNewTarget("");
      setNewChannelError(null);
    },
    onError: () => setNewChannelError("No se pudo crear el canal. Revisa los datos."),
  });

  const notify = useMutation({
    mutationFn: async () =>
      (await notificationApi.post<{ results: NotifyLogOut[] }>("/notify", { subject, body, severity: "info" })).data,
    onSuccess: (data) => {
      setSendFeedback(data.results);
      queryClient.invalidateQueries({ queryKey: ["notification-logs"] });
      setSubject("");
      setBody("");
    },
    onError: () => setSendFeedback([]),
  });

  const targetLabel = newType === "email" ? "Email de destino" : "URL del webhook";
  const targetPlaceholder =
    newType === "email"
      ? "soc@tuempresa.com"
      : newType === "slack_webhook"
      ? "https://hooks.slack.com/services/..."
      : "https://tu-endpoint.tuempresa.com/webhook";

  return (
    <div>
      <PageHeader
        title="Notificaciones"
        subtitle="Canales de aviso (email/Slack/webhook). Por defecto en modo DRY-RUN: no envia nada real hasta que un operador lo habilite explicitamente."
      />

      <div className="panel">
        <h2>Canales configurados</h2>
        {channels.data && (
          <table className="data-table">
            <thead>
              <tr><th>Nombre</th><th>Tipo</th><th>Destino</th><th>Habilitado</th></tr>
            </thead>
            <tbody>
              {channels.data.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.channel_type}</td>
                  <td className="mono">{String(c.config.webhook_url ?? c.config.smtp_to ?? "-")}</td>
                  <td>{c.enabled ? "si" : "no"}</td>
                </tr>
              ))}
              {channels.data.length === 0 && (
                <tr><td colSpan={4} className="empty-hint">Sin canales configurados todavia. Agrega uno abajo.</td></tr>
              )}
            </tbody>
          </table>
        )}

        {canManageChannels ? (
          <div className="inline-form" style={{ marginTop: 12 }}>
            <input placeholder="Nombre del canal" value={newName} onChange={(e) => setNewName(e.target.value)} />
            <select value={newType} onChange={(e) => setNewType(e.target.value as ChannelType)}>
              <option value="slack_webhook">Slack (webhook)</option>
              <option value="generic_webhook">Webhook generico</option>
              <option value="email">Email (SMTP)</option>
            </select>
            <input
              placeholder={targetPlaceholder}
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
            />
            <button
              className="btn-primary"
              onClick={() => createChannel.mutate()}
              disabled={createChannel.isPending || !newName || !newTarget}
            >
              {createChannel.isPending ? "Agregando..." : "Agregar canal"}
            </button>
          </div>
        ) : (
          <p className="empty-hint" style={{ marginTop: 12 }}>
            Tu usuario ({claims?.role ?? "sin rol"}) no puede agregar canales -- lo puede hacer un admin o soc_manager.
          </p>
        )}
        {newType === "email" && (
          <p className="empty-hint">
            El email usa el SMTP configurado en el .env del servidor (SMTP_HOST/PORT/USER/PASSWORD) -- este campo es
            solo el destinatario.
          </p>
        )}
        {newChannelError && <p className="error-text">{newChannelError}</p>}
      </div>

      <div className="panel">
        <h2>Enviar notificacion de prueba</h2>
        {enabledChannelsCount === 0 && (
          <p className="empty-hint">
            No hay ningun canal habilitado todavia -- agrega uno arriba antes de probar el envio.
          </p>
        )}
        <div className="inline-form">
          <input placeholder="Asunto" value={subject} onChange={(e) => setSubject(e.target.value)} />
          <input placeholder="Mensaje" value={body} onChange={(e) => setBody(e.target.value)} />
          <button
            className="btn-primary"
            onClick={() => notify.mutate()}
            disabled={notify.isPending || !subject || enabledChannelsCount === 0}
          >
            {notify.isPending ? "Enviando..." : `Enviar a ${enabledChannelsCount} canal(es) habilitado(s)`}
          </button>
        </div>
        {sendFeedback !== null && (
          <div style={{ marginTop: 10 }}>
            {sendFeedback.length === 0 ? (
              <p className="error-text">No se pudo enviar (revisa la consola del servidor o los canales).</p>
            ) : (
              sendFeedback.map((r) => (
                <p key={r.id} className={r.status === "failed" ? "error-text" : "empty-hint"}>
                  {r.channel_type}: <StatusBadge value={r.status} />
                  {r.error ? ` -- ${r.error}` : ""}
                  {r.status === "simulated" ? " (modo DRY-RUN: no se manda nada real todavia, ver docs/runbook.md)" : ""}
                </p>
              ))
            )}
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Historial de envios</h2>
        {logs.data && (
          <table className="data-table">
            <thead>
              <tr><th>Asunto</th><th>Canal</th><th>Estado</th><th>Error</th><th>Fecha</th></tr>
            </thead>
            <tbody>
              {logs.data.map((l) => (
                <tr key={l.id}>
                  <td>{l.subject}</td>
                  <td>{l.channel_type}</td>
                  <td><StatusBadge value={l.status} /></td>
                  <td>{l.error || "-"}</td>
                  <td>{new Date(l.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {logs.data.length === 0 && (
                <tr><td colSpan={5} className="empty-hint">Sin envios todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
