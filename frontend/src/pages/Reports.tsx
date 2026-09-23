import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { reportApi } from "../services/api";
import type { GeneratedReportOut } from "../types";
import PageHeader from "../components/PageHeader";
import { connectionErrorDetail } from "../utils/errors";

const REPORT_TYPES = [
  { value: "executive_summary", label: "Resumen ejecutivo" },
  { value: "vulnerabilities", label: "Vulnerabilidades" },
  { value: "incidents", label: "Incidentes" },
  { value: "attack_coverage", label: "Cobertura ATT&CK" },
];


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

export default function Reports() {
  const [reportType, setReportType] = useState(REPORT_TYPES[0].value);
  const queryClient = useQueryClient();

  const reports = useQuery({
    queryKey: ["reports"],
    queryFn: async () => (await reportApi.get<GeneratedReportOut[]>("/reports")).data,
  });

  const generate = useMutation({
    mutationFn: async () => (await reportApi.post<GeneratedReportOut>("/reports/generate", { report_type: reportType })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
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
                  </td>
                </tr>
              ))}
              {reports.data.length === 0 && (
                <tr><td colSpan={5} className="empty-hint">Sin reportes generados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
