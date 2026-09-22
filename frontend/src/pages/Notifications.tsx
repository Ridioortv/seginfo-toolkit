import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { notificationApi } from "../services/api";
import type { ChannelOut, NotifyLogOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";

export default function Notifications() {
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const queryClient = useQueryClient();

  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: async () => (await notificationApi.get<ChannelOut[]>("/channels")).data,
  });
  const logs = useQuery({
    queryKey: ["notification-logs"],
    queryFn: async () => (await notificationApi.get<NotifyLogOut[]>("/logs")).data,
  });

  const notify = useMutation({
    mutationFn: async () => (await notificationApi.post("/notify", { subject, body, severity: "info" })).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notification-logs"] });
      setSubject("");
      setBody("");
    },
  });

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
              <tr><th>Nombre</th><th>Tipo</th><th>Habilitado</th></tr>
            </thead>
            <tbody>
              {channels.data.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.channel_type}</td>
                  <td>{c.enabled ? "si" : "no"}</td>
                </tr>
              ))}
              {channels.data.length === 0 && (
                <tr><td colSpan={3} className="empty-hint">Sin canales configurados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Enviar notificacion de prueba</h2>
        <div className="inline-form">
          <input placeholder="Asunto" value={subject} onChange={(e) => setSubject(e.target.value)} />
          <input placeholder="Mensaje" value={body} onChange={(e) => setBody(e.target.value)} />
          <button className="btn-primary" onClick={() => notify.mutate()} disabled={notify.isPending || !subject}>
            {notify.isPending ? "Enviando..." : "Enviar a todos los canales habilitados"}
          </button>
        </div>
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
