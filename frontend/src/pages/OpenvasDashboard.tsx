import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanApi } from "../services/api";
import type { GvmCredentialOut, GvmTargetOut, GvmTaskOut, GvmEntityOut, OpenvasStatusOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail, blobExportErrorDetail } from "../utils/errors";

// Dashboard de administracion avanzada de OpenVAS -- credenciales de
// escaneo autenticado, targets reutilizables y gestion/exportacion de
// analisis(reportes), todo contra gvmd real via los endpoints
// /openvas/{credentials,targets,tasks,reports,port-lists} de
// scan-service (ver app/gvm_manage.py y app/main.py). Separado de
// Scans.tsx (que solo activa OpenVAS y lanza escaneos) porque esto es
// administracion de recursos reutilizables entre escaneos, no un paso
// del flujo de "lanzar un escaneo".

type CredForm = { name: string; login: string; password: string };
const EMPTY_CRED_FORM: CredForm = { name: "", login: "", password: "" };

type TargetForm = { name: string; hosts: string; port_list_id: string; ssh_credential_id: string; smb_credential_id: string };
const EMPTY_TARGET_FORM: TargetForm = { name: "", hosts: "", port_list_id: "", ssh_credential_id: "", smb_credential_id: "" };

type ExportFormat = "pdf" | "xml" | "csv";
const EXPORT_MEDIA_TYPES: Record<ExportFormat, string> = { pdf: "application/pdf", xml: "application/xml", csv: "text/csv" };

async function downloadOpenvasReport(reportId: string, format: ExportFormat) {
  const response = await scanApi.get(`/openvas/reports/${reportId}/export`, {
    params: { format },
    responseType: "blob",
  });
  const url = window.URL.createObjectURL(new Blob([response.data], { type: EXPORT_MEDIA_TYPES[format] }));
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `openvas-reporte-${reportId}.${format}`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export default function OpenvasDashboard() {
  const queryClient = useQueryClient();

  const openvasStatus = useQuery({
    queryKey: ["openvas-status"],
    queryFn: async () => (await scanApi.get<OpenvasStatusOut>("/openvas/status")).data,
  });
  const ready = openvasStatus.data?.ready ?? false;

  const credentials = useQuery({
    queryKey: ["openvas-credentials"],
    queryFn: async () => (await scanApi.get<GvmCredentialOut[]>("/openvas/credentials")).data,
    enabled: ready,
  });
  const targets = useQuery({
    queryKey: ["openvas-targets"],
    queryFn: async () => (await scanApi.get<GvmTargetOut[]>("/openvas/targets")).data,
    enabled: ready,
  });
  // Los analisis en curso cambian de estado/progreso solos (gvmd los va
  // actualizando) -- refetch periodico para que la barra de progreso se
  // mueva sin que el usuario tenga que recargar la pagina a mano.
  const tasks = useQuery({
    queryKey: ["openvas-tasks"],
    queryFn: async () => (await scanApi.get<GvmTaskOut[]>("/openvas/tasks")).data,
    enabled: ready,
    refetchInterval: 15000,
  });
  const portLists = useQuery({
    queryKey: ["openvas-port-lists"],
    queryFn: async () => (await scanApi.get<GvmEntityOut[]>("/openvas/port-lists")).data,
    enabled: ready,
  });

  const [credForm, setCredForm] = useState<CredForm>(EMPTY_CRED_FORM);
  const [credError, setCredError] = useState<string | null>(null);
  const createCredential = useMutation({
    mutationFn: async () => (await scanApi.post<GvmCredentialOut>("/openvas/credentials", credForm)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["openvas-credentials"] });
      setCredForm(EMPTY_CRED_FORM);
      setCredError(null);
    },
  });
  const deleteCredential = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/openvas/credentials/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["openvas-credentials"] }),
  });

  const [targetForm, setTargetForm] = useState<TargetForm>(EMPTY_TARGET_FORM);
  const [targetError, setTargetError] = useState<string | null>(null);
  const createTarget = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<GvmTargetOut>("/openvas/targets", {
          name: targetForm.name,
          hosts: targetForm.hosts,
          port_list_id: targetForm.port_list_id,
          ssh_credential_id: targetForm.ssh_credential_id || null,
          smb_credential_id: targetForm.smb_credential_id || null,
        })
      ).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["openvas-targets"] });
      setTargetForm(EMPTY_TARGET_FORM);
      setTargetError(null);
    },
  });
  const deleteTarget = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/openvas/targets/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["openvas-targets"] }),
  });

  const deleteTask = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/openvas/tasks/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["openvas-tasks"] }),
  });

  const [exportErrorState, setExportErrorState] = useState<string | null>(null);
  const exportTaskReport = useMutation({
    mutationFn: async ({ reportId, format }: { reportId: string; format: ExportFormat }) =>
      downloadOpenvasReport(reportId, format),
    onSuccess: () => setExportErrorState(null),
    onError: async (err) => setExportErrorState(await blobExportErrorDetail(err)),
  });

  function onSubmitCredential() {
    setCredError(null);
    if (!credForm.name.trim() || !credForm.login.trim() || !credForm.password.trim()) {
      setCredError("Completa nombre, usuario y contraseña.");
      return;
    }
    createCredential.mutate();
  }

  function onSubmitTarget() {
    setTargetError(null);
    if (!targetForm.name.trim() || !targetForm.hosts.trim()) {
      setTargetError("Completa nombre y hosts.");
      return;
    }
    if (!targetForm.port_list_id) {
      setTargetError("Elegi una lista de puertos.");
      return;
    }
    createTarget.mutate();
  }

  function credentialNameFor(credentialId: string | null): string {
    if (!credentialId) return "-";
    return credentials.data?.find((c) => c.id === credentialId)?.name ?? "(credencial de otra organizacion)";
  }

  function targetNameFor(targetId: string | null): string {
    if (!targetId) return "-";
    return targets.data?.find((t) => t.id === targetId)?.name ?? targetId;
  }

  if (!openvasStatus.isLoading && !ready) {
    return (
      <div>
        <PageHeader
          title="OpenVAS -- administracion avanzada"
          subtitle="Credenciales de escaneo autenticado, targets reutilizables y analisis/reportes de OpenVAS."
        />
        <div className="panel">
          <p className="empty-hint">
            OpenVAS todavia no esta activado en esta instalacion. Activalo primero desde{" "}
            <Link to="/scans">Escaneos</Link> (boton "Activar OpenVAS") para poder administrar credenciales, targets
            y analisis desde aca.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="OpenVAS -- administracion avanzada"
        subtitle="Credenciales de escaneo autenticado, targets reutilizables para analisis repetidos, y gestion/exportacion de reportes -- todo contra el motor GVM real, sin JSON a mano."
      />

      <div className="panel">
        <h2>Credenciales de escaneo autenticado</h2>
        <p className="empty-hint">
          Usuario y contraseña (SSH o SMB) para que OpenVAS escanee por dentro del sistema operativo -- encuentra
          mas fallos que un escaneo sin credenciales. Quedan guardadas en el motor OpenVAS, nunca en esta
          plataforma.
        </p>
        <div className="inline-form">
          <input
            placeholder="Nombre"
            value={credForm.name}
            onChange={(e) => setCredForm((f) => ({ ...f, name: e.target.value }))}
          />
          <input
            placeholder="Usuario"
            value={credForm.login}
            onChange={(e) => setCredForm((f) => ({ ...f, login: e.target.value }))}
          />
          <input
            type="password"
            placeholder="Contraseña"
            value={credForm.password}
            onChange={(e) => setCredForm((f) => ({ ...f, password: e.target.value }))}
          />
          <button className="btn-primary" onClick={onSubmitCredential} disabled={createCredential.isPending}>
            {createCredential.isPending ? "Creando..." : "Crear credencial"}
          </button>
        </div>
        {credError && <p className="error-text">{credError}</p>}
        {createCredential.isError && !credError && (
          <p className="error-text">
            No se pudo crear la credencial.{" "}
            <span className="error-detail">{connectionErrorDetail(createCredential.error)}</span>
          </p>
        )}

        <table className="data-table" style={{ marginTop: 12 }}>
          <thead>
            <tr><th>Nombre</th><th>Usuario</th><th>Tipo</th><th></th></tr>
          </thead>
          <tbody>
            {credentials.data?.map((c) => (
              <tr key={c.id}>
                <td>{c.name}</td>
                <td className="mono">{c.login}</td>
                <td>{c.credential_type || "-"}</td>
                <td><button className="btn-link" onClick={() => deleteCredential.mutate(c.id)}>Eliminar</button></td>
              </tr>
            ))}
            {credentials.data?.length === 0 && (
              <tr><td colSpan={4} className="empty-hint">Sin credenciales creadas todavia.</td></tr>
            )}
          </tbody>
        </table>
        {deleteCredential.isError && (
          <p className="error-text">
            No se pudo eliminar la credencial.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteCredential.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Targets reutilizables</h2>
        <p className="empty-hint">
          Un target agrupa hosts + lista de puertos + credenciales opcionales, para no tener que volver a
          tipearlos en cada analisis.
        </p>
        <div className="inline-form">
          <input
            placeholder="Nombre"
            value={targetForm.name}
            onChange={(e) => setTargetForm((f) => ({ ...f, name: e.target.value }))}
          />
          <input
            placeholder="Hosts (ej. 192.168.0.10, 192.168.0.0/24)"
            style={{ flex: 2 }}
            value={targetForm.hosts}
            onChange={(e) => setTargetForm((f) => ({ ...f, hosts: e.target.value }))}
          />
        </div>
        <div className="inline-form" style={{ marginTop: 8 }}>
          <select
            value={targetForm.port_list_id}
            onChange={(e) => setTargetForm((f) => ({ ...f, port_list_id: e.target.value }))}
          >
            <option value="">Lista de puertos...</option>
            {portLists.data?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <select
            value={targetForm.ssh_credential_id}
            onChange={(e) => setTargetForm((f) => ({ ...f, ssh_credential_id: e.target.value }))}
          >
            <option value="">Sin credencial SSH</option>
            {credentials.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <select
            value={targetForm.smb_credential_id}
            onChange={(e) => setTargetForm((f) => ({ ...f, smb_credential_id: e.target.value }))}
          >
            <option value="">Sin credencial SMB</option>
            {credentials.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <button className="btn-primary" onClick={onSubmitTarget} disabled={createTarget.isPending}>
            {createTarget.isPending ? "Creando..." : "Crear target"}
          </button>
        </div>
        {targetError && <p className="error-text">{targetError}</p>}
        {createTarget.isError && !targetError && (
          <p className="error-text">
            No se pudo crear el target.{" "}
            <span className="error-detail">{connectionErrorDetail(createTarget.error)}</span>
          </p>
        )}
        {portLists.isError && (
          <p className="error-text">
            No se pudieron cargar las listas de puertos disponibles.{" "}
            <span className="error-detail">{connectionErrorDetail(portLists.error)}</span>
          </p>
        )}

        <table className="data-table" style={{ marginTop: 12 }}>
          <thead>
            <tr><th>Nombre</th><th>Hosts</th><th>SSH</th><th>SMB</th><th></th></tr>
          </thead>
          <tbody>
            {targets.data?.map((t) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td className="mono">{t.hosts}</td>
                <td>{credentialNameFor(t.ssh_credential_id)}</td>
                <td>{credentialNameFor(t.smb_credential_id)}</td>
                <td><button className="btn-link" onClick={() => deleteTarget.mutate(t.id)}>Eliminar</button></td>
              </tr>
            ))}
            {targets.data?.length === 0 && (
              <tr><td colSpan={5} className="empty-hint">Sin targets creados todavia.</td></tr>
            )}
          </tbody>
        </table>
        {deleteTarget.isError && (
          <p className="error-text">
            No se pudo eliminar el target.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteTarget.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Analisis y reportes</h2>
        <p className="empty-hint">
          Cada analisis OpenVAS lanzado (desde "Escaneos", eligiendo el scanner "openvas") aparece aca con su
          progreso real y, al terminar, permite exportar el reporte completo en PDF, CSV o XML.
        </p>
        <table className="data-table">
          <thead>
            <tr><th>Nombre</th><th>Estado</th><th>Progreso</th><th>Target</th><th>Reporte</th><th></th></tr>
          </thead>
          <tbody>
            {tasks.data?.map((t) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td><StatusBadge value={t.status.toLowerCase()} /></td>
                <td>
                  <div className="progress-bar-track" style={{ minWidth: 80 }}>
                    <div className="progress-bar-fill" style={{ width: `${t.progress}%` }} />
                  </div>
                </td>
                <td>{targetNameFor(t.target_id)}</td>
                <td>
                  {t.last_report_id ? (
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        className="btn-link"
                        disabled={exportTaskReport.isPending}
                        onClick={() => exportTaskReport.mutate({ reportId: t.last_report_id!, format: "pdf" })}
                      >
                        PDF
                      </button>
                      <button
                        className="btn-link"
                        disabled={exportTaskReport.isPending}
                        onClick={() => exportTaskReport.mutate({ reportId: t.last_report_id!, format: "csv" })}
                      >
                        CSV
                      </button>
                      <button
                        className="btn-link"
                        disabled={exportTaskReport.isPending}
                        onClick={() => exportTaskReport.mutate({ reportId: t.last_report_id!, format: "xml" })}
                      >
                        XML
                      </button>
                    </div>
                  ) : (
                    "-"
                  )}
                </td>
                <td><button className="btn-link" onClick={() => deleteTask.mutate(t.id)}>Eliminar</button></td>
              </tr>
            ))}
            {tasks.data?.length === 0 && (
              <tr><td colSpan={6} className="empty-hint">Sin analisis OpenVAS todavia.</td></tr>
            )}
          </tbody>
        </table>
        {deleteTask.isError && (
          <p className="error-text">
            No se pudo eliminar el analisis.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteTask.error)}</span>
          </p>
        )}
        {exportErrorState && (
          <p className="error-text">
            No se pudo exportar el reporte.{" "}
            <span className="error-detail">{exportErrorState}</span>
          </p>
        )}
      </div>
    </div>
  );
}
