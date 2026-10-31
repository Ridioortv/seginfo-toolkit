import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { integrationApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import { connectionErrorDetail } from "../utils/errors";
import { PROVIDER_LABEL, STATE_BADGE, STATE_LABEL, hasActiveTicket, ticketErrorText, type TicketLink } from "../utils/tickets";
import { currentLocale, t } from "../i18n";

const CAN_CREATE = ["admin", "soc_manager", "analyst"];

/** Tickets de Jira / ServiceNow vinculados a una vulnerabilidad o a un caso, con el boton para abrir uno. */
export default function TicketLinks({ subjectType, subjectId }: { subjectType: "vulnerability" | "case"; subjectId: string }) {
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const key = ["ticket-links", subjectType, subjectId];
  const links = useQuery({
    queryKey: key,
    queryFn: async () => (await integrationApi.get<TicketLink[]>("/ticket-links", { params: { subject_type: subjectType, subject_id: subjectId } })).data,
  });
  const connectors = useQuery({
    queryKey: ["connectors", "ticketing"],
    queryFn: async () => (await integrationApi.get<{ id: string; enabled: boolean }[]>("/connectors", { params: { kind: "ticketing" } })).data,
  });
  const create = useMutation({
    mutationFn: async () => (await integrationApi.post<TicketLink>("/ticket-links", { subject_type: subjectType, subject_id: subjectId })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: key }),
  });
  const sync = useMutation({
    mutationFn: async (id: string) => (await integrationApi.post<TicketLink>(`/ticket-links/${id}/sync`)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: key }),
  });

  const list = links.data ?? [];
  const hasConnector = (connectors.data ?? []).some((c) => c.enabled);
  const createError = create.error && isAxiosError(create.error) ? ticketErrorText(create.error.response?.data?.detail, connectionErrorDetail(create.error)) : create.error ? connectionErrorDetail(create.error) : "";
  return (
    <div style={{ margin: "10px 0" }}>
      <strong>{t("Tickets")}</strong>
      {links.isLoading && <span className="empty-hint"> {t("Cargando...")}</span>}
      {list.length === 0 && !links.isLoading && <p className="empty-hint" style={{ margin: "4px 0" }}>{t("Todavia no hay un ticket para esto.")}</p>}
      {list.map((l) => (
        <div key={l.id} style={{ margin: "6px 0" }}>
          <span className={STATE_BADGE[l.state]}>{t(STATE_LABEL[l.state])}</span>{" "}
          {l.external_url ? <a href={l.external_url} target="_blank" rel="noreferrer">{l.external_key}</a> : l.external_key || "-"}{" "}
          <span className="empty-hint">{PROVIDER_LABEL[l.provider] ?? l.provider}{l.external_status && ` - ${l.external_status}`}</span>
          {l.applied_note && <div className="empty-hint">{l.applied_note}</div>}
          {l.last_error && <div className="error-text"><span className="error-detail">{l.last_error}</span></div>}
          {l.last_synced_at && <div className="empty-hint">{t("Ultima consulta: {0}", new Date(l.last_synced_at).toLocaleString(currentLocale()))}</div>}
          {CAN_CREATE.includes(role) && (l.state === "open" || (l.state === "resolved" && !l.applied)) && (
            <button className="btn-link" disabled={sync.isPending} onClick={() => sync.mutate(l.id)}>{t("Actualizar estado")}</button>
          )}
        </div>
      ))}
      {CAN_CREATE.includes(role) && !hasActiveTicket(list) && (
        <div>
          <button className="btn-secondary" disabled={create.isPending || !hasConnector} onClick={() => create.mutate()}>
            {create.isPending ? t("Creando...") : t("Crear ticket")}
          </button>
          {!hasConnector && !connectors.isLoading && <span className="empty-hint"> {t("Primero configura un conector de tickets en Integraciones.")}</span>}
        </div>
      )}
      {createError && <p className="error-text"><span className="error-detail">{createError}</span></p>}
      {sync.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(sync.error)}</span></p>}
    </div>
  );
}
