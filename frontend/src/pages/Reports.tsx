import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { reportApi, notificationApi } from "../services/api";
import type { GeneratedReportOut, ReportScheduleOut, ChannelOut } from "../types";
import PageHeader from "../components/PageHeader";
import { connectionErrorDetail } from "../utils/errors";

const REPORT_TYPES = [
  { value: "executive_summary", label: "Resumen ejecutivo" },
  { value: "vulnerabilities", label: "Vulnerabilidades" },
  { value: "incidents", label: "Incidentes" },
  { value: "attack_coverage", label: "Cobertura ATT&CK" },
];

const DAY_LABELS = ["Lunes", "Martes", "Miercoles", "Jueves", "Viernes", "Sabado", "Domingo"];

function scheduleWhen(s: ReportScheduleOut): string {
  const time = `${String(s.hour).padStart(2, "0")}:${String(s.minute).padStart(2, "0")}`;
  if (s.frequency === "weekly") {
    return `Todos los ${DAY_LABELS[s.day_of_week ?? 0]} a las ${time}`;
  }
  return `Todos los dias a las ${time}`;
}

async function downloadCsv(reportId: string) {
  const response = await reportApi.get(`/reports/${reportId}/export`, {
    params: { format: "csv" },
    responseType: "blob",
  });
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `reporte-${reportId}.csv`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

async function downloadPdf(reportId: string) {
  const response = await reportApi.get(`/reports/${reportId}/export`, {
    params: { format: "pdf" },
    responseType: "blob",
  });
  const url = window.URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `reporte-${reportId}.pdf`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export default function Reports() {
  const [reportType, setReportType] = useState(REPORT_TYPES[0].value);
  const queryClient = useQueryClient();

  const [schedReportType, setSchedReportType] = useState(REPORT_TYPES[0].value);
  const [schedChannelId, setSchedChannelId] = useState("");
  const [schedFrequency, setSchedFrequency] = useState<"daily" | "weekly">("daily");
  const [schedDayOfWeek, setSchedDayOfWeek] = useState(0);
  const [schedHour, setSchedHour] = useState(8);
  const [schedMinute, setSchedMinute] = useState(0);

  const reports = useQuery({
    queryKey: ["reports"],
    queryFn: async () => (await reportApi.get<GeneratedReportOut[]>("/reports")).data,
  });

  const channels = useQuery({
    queryKey: ["notification-channels"],
    queryFn: async () => (await notificationApi.get<ChannelOut[]>("/channels")).data,
  });
  const emailChannels = (channels.data ?? []).filter((c) => c.channel_type === "email" && c.enabled);

  const schedules = useQuery({
    queryKey: ["report-schedules"],
    queryFn: async () => (await reportApi.get<ReportScheduleOut[]>("/report-schedules")).data,
  });

  const generate = useMutation({
    mutationFn: async () => (await reportApi.post<GeneratedReportOut>("/reports/generate", { report_type: reportType })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
  });

  const deleteReport = useMutation({
    mutationFn: async (id: string) => reportApi.delete(`/reports/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
  });

  const createSchedule = useMutation({
    mutationFn: async () =>
      (
        await reportApi.post<ReportScheduleOut>("/report-schedules", {
          report_type: schedReportType,
          notification_channel_id: schedChannelId,
          frequency: schedFrequency,
          hour: schedHour,
          minute: schedMinute,
          day_of_week: schedFrequency === "weekly" ? schedDayOfWeek : null,
        })
      ).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["report-schedules"] }),
  });

  const toggleSchedule = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      (await reportApi.patch<ReportScheduleOut>(`/report-schedules/${id}`, { enabled })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["report-schedules"] }),
  });

  const deleteSchedule = useMutation({
    mutationFn: async (id: string) => reportApi.delete(`/report-schedules/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["report-schedules"] }),
  });

  return (
    <div>
      <PageHeader
        title="Reportes"
        subtitle="Reportes ejecutivos y de cumplimiento generados 100% a partir de datos de otros servicios -- nunca datos inventados"
      />

      <div className="panel">
        <div className="inline-form">
          <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
            {REPORT_TYPES.map((rt) => (
              <option key={rt.value} value={rt.value}>{rt.label}</option>
            ))}
          </select>
          <button className="btn-primary" onClick={() => generate.mutate()} disabled={generate.isPending}>
            {generate.isPending ? "Generando..." : "Generar reporte"}
          </button>
        </div>
        {generate.isError && (
          <p className="error-text">
            No se pudo generar el reporte.{" "}
            <span className="error-detail">{connectionErrorDetail(generate.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Historial</h2>
        {reports.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Tipo</th>
                <th>Generado por</th>
                <th>Errores</th>
                <th>Fecha</th>
                <th>Export</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {reports.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.report_type}</td>
                  <td>{r.generated_by || "-"}</td>
                  <td>{r.errors.length > 0 ? r.errors.join("; ") : "-"}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                  <td>
                    <button className="btn-link" onClick={() => downloadCsv(r.id)}>CSV</button>
                    {" / "}
                    <button className="btn-link" onClick={() => downloadPdf(r.id)}>PDF</button>
                  </td>
                  <td>
                    <button className="btn-link" onClick={() => deleteReport.mutate(r.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
              {reports.data.length === 0 && (
                <tr><td colSpan={6} className="empty-hint">Sin reportes generados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Reportes programados</h2>
        <p className="empty-hint">
          Una regla genera el reporte solo y lo manda por email como PDF adjunto al canal elegido (necesita al menos
          un canal de notificaciones tipo "email" ya creado -- ver la pagina de Integraciones/Notificaciones). Corre
          mientras report-service este arriba (scheduler en proceso, sin infraestructura extra); si el contenedor se
          reinicia, las reglas habilitadas se vuelven a cargar solas al arrancar.
        </p>

        {emailChannels.length === 0 && (
          <p className="empty-hint">No hay ningun canal de notificaciones tipo "email" habilitado todavia.</p>
        )}

        <div className="inline-form">
          <select value={schedReportType} onChange={(e) => setSchedReportType(e.target.value)}>
            {REPORT_TYPES.map((rt) => (
              <option key={rt.value} value={rt.value}>{rt.label}</option>
            ))}
          </select>
          <select value={schedChannelId} onChange={(e) => setSchedChannelId(e.target.value)}>
            <option value="">Elegir canal de email...</option>
            {emailChannels.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
        </div>
        <div className="inline-form" style={{ marginTop: 8 }}>
          <select value={schedFrequency} onChange={(e) => setSchedFrequency(e.target.value as "daily" | "weekly")}>
            <option value="daily">Todos los dias</option>
            <option value="weekly">Un dia a la semana</option>
          </select>
          {schedFrequency === "weekly" && (
            <select value={schedDayOfWeek} onChange={(e) => setSchedDayOfWeek(Number(e.target.value))}>
              {DAY_LABELS.map((label, idx) => (
                <option key={label} value={idx}>{label}</option>
              ))}
            </select>
          )}
          <input
            type="number" min={0} max={23} style={{ width: 60 }}
            value={schedHour} onChange={(e) => setSchedHour(Number(e.target.value))}
          />
          <span>:</span>
          <input
            type="number" min={0} max={59} style={{ width: 60 }}
            value={schedMinute} onChange={(e) => setSchedMinute(Number(e.target.value))}
          />
          <button
            className="btn-primary"
            onClick={() => createSchedule.mutate()}
            disabled={createSchedule.isPending || !schedChannelId}
          >
            {createSchedule.isPending ? "Creando..." : "Crear regla"}
          </button>
        </div>
        {createSchedule.isError && (
          <p className="error-text">
            No se pudo crear la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(createSchedule.error)}</span>
          </p>
        )}

        {schedules.data && schedules.data.length > 0 && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Tipo</th>
                <th>Canal</th>
                <th>Cuando</th>
                <th>Ultima corrida</th>
                <th>Habilitada</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {schedules.data.map((s) => (
                <tr key={s.id}>
                  <td>{REPORT_TYPES.find((rt) => rt.value === s.report_type)?.label ?? s.report_type}</td>
                  <td>{(channels.data ?? []).find((c) => c.id === s.notification_channel_id)?.name ?? s.notification_channel_id}</td>
                  <td>{scheduleWhen(s)}</td>
                  <td>
                    {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "nunca"}
                    {s.last_status && <span className="error-detail">{s.last_status}</span>}
                  </td>
                  <td>
                    <input
                      type="checkbox"
                      checked={s.enabled}
                      onChange={(e) => toggleSchedule.mutate({ id: s.id, enabled: e.target.checked })}
                    />
                  </td>
                  <td>
                    <button className="btn-link" onClick={() => deleteSchedule.mutate(s.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
