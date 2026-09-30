// Dashboard propio de OpenVAS/GVM (ver pedido original: "quiero que
// openvas abra un dashboard propio... y se puedan hacer analisis desde
// ahi... con todas las funcionalidades de openvas al 100%"). Fase 1
// (alcance acordado con el usuario via preguntas de scoping): elegir tipo
// de escaneo (config), credenciales para escaneo autenticado, targets
// guardados y reutilizables, y reportes completos exportables -- todo
// contra gvmd real via app/gvm_manage.py (ver backend), gvmd es la unica
// fuente de verdad de targets/credenciales (no hay base local propia).
//
// Fases futuras (parte de la "replica completa de la interfaz de GVM"
// que el usuario eligio como objetivo final, pendientes de este primer
// entregable): alertas nativas de GVM, formatos de reporte personalizados,
// politicas de escaneo editables a mano, usuarios/roles propios de GVM, y
// exploracion de los feeds NVT/CVE.
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanApi } from "../services/api";
import type { OpenvasStatusOut, GvmEntityOut, GvmCredentialOut, GvmTargetOut, GvmTaskOut } from "../types";
import PageHeader from "../components/PageHeader";
import { connectionErrorDetail } from "../utils/errors";

const DAY_LABELS = ["Lunes", "Martes", "Miercoles", "Jueves", "Viernes", "Sabado", "Domingo"];

// Mismos 3 formatos que exporta app/gvm_manage.py::export_report -- ver
// _EXPORT_FORMAT_NAMES en el backend (pdf/xml/csv, nada mas).
const EXPORT_FORMATS: { value: "pdf" | "xml" | "csv"; label: string }[] = [
  { value: "pdf", label: "PDF" },
  { value: "xml", label: "XML" },
  { value: "csv", label: "CSV" },
];

// Colores de badge reutilizados de app/components/Badge.tsx (que solo
// cubre severidad/estados de ScanJob) para los status nativos de GVM
// (Done/Running/Requested/New/Stopped/Interrupted) -- son literal el
// texto que devuelve gvmd, no vale la pena traducirlos.
const TASK_STATUS_CLASS: Record<string, string> = {
  Done: "badge badge-success",
  Running: "badge badge-medium",
  Requested: "badge badge-medium",
  New: "badge badge-neutral",
  Stopped: "badge badge-high",
  Interrupted: "badge badge-critical",
};

function TaskStatusBadge({ value }: { value: string }) {
  return <span className={TASK_STATUS_CLASS[value] ?? "badge badge-neutral"}>{value}</span>;
}

// Mismo patron de descarga por blob que Reports.tsx::downloadCsv/downloadPdf
// -- GET con responseType "blob", crear un <a download> sintetico y
// dispararle click.
async function downloadOpenvasReport(reportId: string, format: "pdf" | "xml" | "csv") {
  const response = await scanApi.get(`/openvas/reports/${reportId}/export`, {
    params: { format },
    responseType: "blob",
  });
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `sentinelops-report-${reportId.slice(0, 8)}.${format}`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export default function OpenvasDashboard() {
  const queryClient = useQueryClient();

  // Misma queryKey "openvas-status" que usa Scans.tsx -- comparten cache,
  // asi si el usuario vuelve a Escaneos y desactiva/reactiva OpenVAS en
  // otra pestaña, esta pagina lo ve sin tener que hacer nada especial.
  const openvasStatus = useQuery({
    queryKey: ["openvas-status"],
    queryFn: async () => (await scanApi.get<OpenvasStatusOut>("/openvas/status")).data,
    refetchInterval: 15_000,
    retry: false,
  });
  const openvasReady = openvasStatus.data?.ready ?? false;

  const configs = useQuery({
    queryKey: ["openvas-configs"],
    queryFn: async () => (await scanApi.get<GvmEntityOut[]>("/openvas/configs")).data,
    enabled: openvasReady,
  });
  const credentials = useQuery({
    queryKey: ["openvas-credentials"],
    queryFn: async () => (await scanApi.get<GvmCredentialOut[]>("/openvas/credentials")).data,
    enabled: openvasReady,
  });
  const portLists = useQuery({
    queryKey: ["openvas-port-lists"],
    queryFn: async () => (await scanApi.get<GvmEntityOut[]>("/openvas/port-lists")).data,
    enabled: openvasReady,
  });
  const targets = useQuery({
    queryKey: ["openvas-targets"],
    queryFn: async () => (await scanApi.get<GvmTargetOut[]>("/openvas/targets")).data,
    enabled: openvasReady,
  });
  const tasks = useQuery({
    queryKey: ["openvas-tasks"],
    queryFn: async () => (await scanApi.get<GvmTaskOut[]>("/openvas/tasks")).data,
    enabled: openvasReady,
    refetchInterval: 10_000,
  });

  // --- Credenciales guardadas (escaneo autenticado SSH/SMB, tipo "up" --
  // usuario+contraseña, ver GvmCredentialCreate en el backend) ---
  const [credName, setCredName] = useState("");
  const [credLogin, setCredLogin] = useState("root");
  const [credPassword, setCredPassword] = useState("");
  const [credActionError, setCredActionError] = useState<unknown>(null);

  const createCredential = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<GvmCredentialOut>("/openvas/credentials", {
          name: credName,
          login: credLogin,
          password: credPassword,
        })
      ).data,
    onSuccess: () => {
      setCredName("");
      setCredPassword("");
      queryClient.invalidateQueries({ queryKey: ["openvas-credentials"] });
    },
  });

  const deleteCredential = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/openvas/credentials/${id}`),
    onSuccess: () => {
      setCredActionError(null);
      queryClient.invalidateQueries({ queryKey: ["openvas-credentials"] });
    },
    onError: (err: unknown) => setCredActionError(err),
  });

  // --- Targets guardados y reutilizables (gvmd es la unica fuente de
  // verdad -- ver create_target/delete_target en app/gvm_manage.py) ---
  const [targetName, setTargetName] = useState("");
  const [targetHosts, setTargetHosts] = useState("");
  const [targetPortListId, setTargetPortListId] = useState("");
  const [targetSshCredId, setTargetSshCredId] = useState("");
  const [targetSmbCredId, setTargetSmbCredId] = useState("");
  const [targetActionError, setTargetActionError] = useState<unknown>(null);

  const createTarget = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<GvmTargetOut>("/openvas/targets", {
          name: targetName,
          hosts: targetHosts,
          port_list_id: targetPortListId,
          ssh_credential_id: targetSshCredId || null,
          smb_credential_id: targetSmbCredId || null,
        })
      ).data,
    onSuccess: () => {
      setTargetName("");
      setTargetHosts("");
      setTargetSshCredId("");
      setTargetSmbCredId("");
      queryClient.invalidateQueries({ queryKey: ["openvas-targets"] });
    },
  });

  const deleteTarget = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/openvas/targets/${id}`),
    onSuccess: () => {
      setTargetActionError(null);
      queryClient.invalidateQueries({ queryKey: ["openvas-targets"] });
    },
    onError: (err: unknown) => setTargetActionError(err),
  });

  // --- Nuevo analisis: elegir target (guardado o nuevo), tipo de
  // escaneo (config), y lanzarlo ahora o programarlo -- reusa /scans y
  // /scan-schedules (con scanner_type="openvas") tal cual ya existian,
  // solo que ahora completa "options" con los overrides gvm_* en vez de
  // dejar que el driver descubra/cree todo solo (ver OpenVasDriver.run
  // en app/scanners/openvas.py: sin overrides el comportamiento es
  // exactamente el de siempre). Los analisis PROGRAMADOS reusan el mismo
  // /scan-schedules generico -- no hace falta scheduling nativo de GVM
  // aparte, porque el driver es el mismo de punta a punta.
  const [scanName, setScanName] = useState("");
  const [scanTargetMode, setScanTargetMode] = useState<"saved" | "new">("saved");
  const [scanTargetId, setScanTargetId] = useState("");
  const [scanAdhocHosts, setScanAdhocHosts] = useState("");
  const [scanConfigId, setScanConfigId] = useState("");
  const [scanWhen, setScanWhen] = useState<"now" | "scheduled">("now");
  const [scanFrequency, setScanFrequency] = useState<"daily" | "weekly">("daily");
  const [scanDayOfWeek, setScanDayOfWeek] = useState(0);
  const [scanHour, setScanHour] = useState(3);
  const [scanMinute, setScanMinute] = useState(0);

  function buildScanPayload() {
    const savedTarget = (targets.data ?? []).find((t) => t.id === scanTargetId);
    const targetHostsValue = scanTargetMode === "saved" ? savedTarget?.hosts ?? "" : scanAdhocHosts.trim();
    const options: Record<string, unknown> = {};
    if (scanConfigId) options.gvm_config_id = scanConfigId;
    if (scanTargetMode === "saved" && scanTargetId) {
      // Target ya existe en gvmd -- el driver lo reusa tal cual, sin crear
      // uno nuevo (ver override_target_id en OpenVasDriver.run).
      options.gvm_target_id = scanTargetId;
    }
    // Modo "target nuevo": no se manda gvm_target_id, asi el driver crea
    // uno el mismo (mismo comportamiento de siempre desde la pantalla
    // generica de Escaneos) -- si el usuario quiere elegir puerto/
    // credenciales de autenticacion para ESE target puntual, primero lo
    // guarda abajo en "Targets guardados" y lo elige como "target
    // guardado" aca.
    return { name: scanName, target: targetHostsValue, options };
  }

  const launchNow = useMutation({
    mutationFn: async () => {
      const payload = buildScanPayload();
      return (await scanApi.post("/scans", { ...payload, scanner_type: "openvas" })).data;
    },
    onSuccess: () => {
      setScanName("");
      queryClient.invalidateQueries({ queryKey: ["openvas-tasks"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const launchScheduled = useMutation({
    mutationFn: async () => {
      const payload = buildScanPayload();
      return (
        await scanApi.post("/scan-schedules", {
          ...payload,
          scanner_type: "openvas",
          frequency: scanFrequency,
          hour: scanHour,
          minute: scanMinute,
          day_of_week: scanFrequency === "weekly" ? scanDayOfWeek : null,
        })
      ).data;
    },
    onSuccess: () => {
      setScanName("");
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
  });

  const targetChosen = scanTargetMode === "saved" ? !!scanTargetId : !!scanAdhocHosts.trim();
  const launchMutation = scanWhen === "now" ? launchNow : launchScheduled;

  // --- Analisis y reportes: tasks nativos de GVM (ver GET /openvas/tasks)
  // -- id/nombre/estado/progreso/target/ultimo reporte, tal como los ve
  // gvmd. La fila expandida trae el XML completo del reporte (sin
  // exportar ningun archivo, GET /openvas/reports/{id}) ademas de los
  // botones de exportar PDF/XML/CSV.
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);
  const [exportError, setExportError] = useState<unknown>(null);

  const report = useQuery({
    queryKey: ["openvas-report", expandedTaskId],
    queryFn: async () => {
      const task = (tasks.data ?? []).find((t) => t.id === expandedTaskId);
      const reportId = task?.last_report_id;
      if (!reportId) return null;
      return (await scanApi.get<{ report_id: string; raw_xml: string }>(`/openvas/reports/${reportId}`)).data;
    },
    enabled: !!expandedTaskId,
  });

  async function handleExport(reportId: string, format: "pdf" | "xml" | "csv") {
    try {
      setExportError(null);
      await downloadOpenvasReport(reportId, format);
    } catch (err) {
      setExportError(err);
    }
  }

  if (openvasStatus.isLoading) {
    return (
      <div>
        <PageHeader title="Dashboard de OpenVAS" />
        <p className="empty-hint">Comprobando el estado de OpenVAS...</p>
      </div>
    );
  }

  if (!openvasReady) {
    return (
      <div>
        <PageHeader title="Dashboard de OpenVAS" subtitle="OpenVAS todavia no esta activo." />
        <div className="panel">
          <p className="empty-hint">
            Este dashboard necesita que OpenVAS este activo y conectado. Volve a{" "}
            <Link to="/scans" className="btn-link">Escaneos</Link> y usa "Arrancar OpenVAS" (o "Probar y activar") --
            en cuanto termine de arrancar, esta pagina se abre sola.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Dashboard de OpenVAS"
        subtitle="Todo OpenVAS/GVM en un solo lugar: elegi tipo de escaneo, credenciales para escaneo autenticado, targets reutilizables y reportes completos exportables."
      />
      <p style={{ marginTop: -12, marginBottom: 20 }}>
        <Link to="/scans" className="btn-link">&larr; Volver a Escaneos</Link>
      </p>

      {/* --- Nuevo analisis --- */}
      <div className="panel">
        <h2>Nuevo analisis</h2>

        <div className="inline-form">
          <input placeholder="Nombre (opcional)" value={scanName} onChange={(e) => setScanName(e.target.value)} />
          <select value={scanConfigId} onChange={(e) => setScanConfigId(e.target.value)}>
            <option value="">Tipo de escaneo: auto (Full and fast)</option>
            {(configs.data ?? []).map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
        </div>
        {configs.isError && (
          <p className="error-text">
            No se pudieron traer los tipos de escaneo de gvmd.{" "}
            <span className="error-detail">{connectionErrorDetail(configs.error)}</span>
          </p>
        )}

        <div className="inline-form" style={{ marginTop: 10 }}>
          <label>
            <input
              type="radio"
              checked={scanTargetMode === "saved"}
              onChange={() => setScanTargetMode("saved")}
            />{" "}
            Target guardado
          </label>
          <label>
            <input
              type="radio"
              checked={scanTargetMode === "new"}
              onChange={() => setScanTargetMode("new")}
            />{" "}
            Target nuevo (sin autenticar)
          </label>
        </div>

        {scanTargetMode === "saved" ? (
          <div className="inline-form" style={{ marginTop: 8 }}>
            <select value={scanTargetId} onChange={(e) => setScanTargetId(e.target.value)}>
              <option value="">Elegir target guardado...</option>
              {(targets.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>{t.name} ({t.hosts})</option>
              ))}
            </select>
            {(targets.data ?? []).length === 0 && (
              <span className="empty-hint">No hay targets guardados todavia (creá uno mas abajo).</span>
            )}
          </div>
        ) : (
          <div className="inline-form" style={{ marginTop: 8 }}>
            <input
              className="mono"
              placeholder="Host, rango o CIDR (ej. 192.168.1.10 o 10.0.0.0/24)"
              value={scanAdhocHosts}
              onChange={(e) => setScanAdhocHosts(e.target.value)}
            />
            <span className="empty-hint">
              Se crea sin credenciales (deteccion de red). Para escaneo autenticado, guardalo abajo eligiendo credenciales.
            </span>
          </div>
        )}

        <div className="inline-form" style={{ marginTop: 14 }}>
          <label>
            <input type="radio" checked={scanWhen === "now"} onChange={() => setScanWhen("now")} /> Ahora
          </label>
          <label>
            <input type="radio" checked={scanWhen === "scheduled"} onChange={() => setScanWhen("scheduled")} /> Programado
          </label>
        </div>

        {scanWhen === "scheduled" && (
          <div className="inline-form" style={{ marginTop: 8 }}>
            <select value={scanFrequency} onChange={(e) => setScanFrequency(e.target.value as "daily" | "weekly")}>
              <option value="daily">Todos los dias</option>
              <option value="weekly">Un dia a la semana</option>
            </select>
            {scanFrequency === "weekly" && (
              <select value={scanDayOfWeek} onChange={(e) => setScanDayOfWeek(Number(e.target.value))}>
                {DAY_LABELS.map((label, idx) => (
                  <option key={label} value={idx}>{label}</option>
                ))}
              </select>
            )}
            <input
              type="number" min={0} max={23} style={{ width: 60 }}
              value={scanHour} onChange={(e) => setScanHour(Number(e.target.value))}
            />
            <span>:</span>
            <input
              type="number" min={0} max={59} style={{ width: 60 }}
              value={scanMinute} onChange={(e) => setScanMinute(Number(e.target.value))}
            />
          </div>
        )}

        <div className="inline-form" style={{ marginTop: 14 }}>
          <button
            className="btn-primary"
            style={{ width: "auto" }}
            onClick={() => launchMutation.mutate()}
            disabled={launchMutation.isPending || !targetChosen}
          >
            {launchMutation.isPending
              ? "Lanzando..."
              : scanWhen === "now"
                ? "Lanzar analisis ahora"
                : "Crear regla programada"}
          </button>
        </div>
        {launchNow.isError && (
          <p className="error-text">
            No se pudo lanzar el analisis.{" "}
            <span className="error-detail">{connectionErrorDetail(launchNow.error)}</span>
          </p>
        )}
        {launchScheduled.isError && (
          <p className="error-text">
            No se pudo crear la regla programada.{" "}
            <span className="error-detail">{connectionErrorDetail(launchScheduled.error)}</span>
          </p>
        )}
        {launchNow.isSuccess && scanWhen === "now" && (
          <p className="empty-hint">
            Analisis lanzado -- seguí su progreso mas abajo en "Analisis y reportes" (o en Escaneos).
          </p>
        )}
        {launchScheduled.isSuccess && scanWhen === "scheduled" && (
          <p className="empty-hint">
            Regla programada creada -- se puede administrar tambien desde Escaneos &rarr; Analisis programados.
          </p>
        )}
      </div>

      {/* --- Credenciales guardadas --- */}
      <div className="panel">
        <h2>Credenciales para escaneo autenticado</h2>
        <p className="empty-hint">
          Usuario+contraseña que gvmd usa para loguearse al host durante el escaneo (SSH o SMB) y detectar mucho mas
          que un escaneo de red comun -- lo que GVM llama "escaneo autenticado". Se guardan en gvmd, igual que los
          targets: se pueden reusar en cualquier target nuevo de mas arriba.
        </p>
        <div className="inline-form">
          <input placeholder="Nombre" value={credName} onChange={(e) => setCredName(e.target.value)} />
          <input placeholder="Usuario" value={credLogin} onChange={(e) => setCredLogin(e.target.value)} />
          <input
            type="password"
            placeholder="Contraseña"
            className="mono"
            value={credPassword}
            onChange={(e) => setCredPassword(e.target.value)}
          />
          <button
            className="btn-secondary"
            onClick={() => createCredential.mutate()}
            disabled={createCredential.isPending || !credName.trim() || !credLogin.trim() || !credPassword.trim()}
          >
            {createCredential.isPending ? "Creando..." : "Crear credencial"}
          </button>
        </div>
        {createCredential.isError && (
          <p className="error-text">
            No se pudo crear la credencial.{" "}
            <span className="error-detail">{connectionErrorDetail(createCredential.error)}</span>
          </p>
        )}
        {credentials.isError && (
          <p className="error-text">
            No se pudieron traer las credenciales de gvmd.{" "}
            <span className="error-detail">{connectionErrorDetail(credentials.error)}</span>
          </p>
        )}

        {(credentials.data ?? []).length > 0 && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Usuario</th>
                <th>Tipo</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(credentials.data ?? []).map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td className="mono">{c.login}</td>
                  <td>{c.credential_type}</td>
                  <td>
                    <button className="btn-link" onClick={() => deleteCredential.mutate(c.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {(credentials.data ?? []).length === 0 && !credentials.isError && (
          <p className="empty-hint">No hay credenciales guardadas todavia.</p>
        )}
        {credActionError != null && (
          <p className="error-text">
            No se pudo borrar la credencial.{" "}
            <span className="error-detail">{connectionErrorDetail(credActionError)}</span>
          </p>
        )}
      </div>

      {/* --- Targets guardados --- */}
      <div className="panel">
        <h2>Targets guardados y reutilizables</h2>
        <p className="empty-hint">
          Un target agrupa host(s)/rango, la lista de puertos a revisar y (opcional) las credenciales de escaneo
          autenticado -- se guarda una sola vez en gvmd y se reusa en cualquier analisis nuevo de mas arriba.
        </p>
        <div className="inline-form">
          <input placeholder="Nombre" value={targetName} onChange={(e) => setTargetName(e.target.value)} />
          <input
            className="mono"
            placeholder="Host, rango o CIDR"
            value={targetHosts}
            onChange={(e) => setTargetHosts(e.target.value)}
          />
          <select value={targetPortListId} onChange={(e) => setTargetPortListId(e.target.value)}>
            <option value="">Lista de puertos...</option>
            {(portLists.data ?? []).map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>
        <div className="inline-form" style={{ marginTop: 8 }}>
          <select value={targetSshCredId} onChange={(e) => setTargetSshCredId(e.target.value)}>
            <option value="">Credencial SSH (opcional)</option>
            {(credentials.data ?? []).map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <select value={targetSmbCredId} onChange={(e) => setTargetSmbCredId(e.target.value)}>
            <option value="">Credencial SMB (opcional)</option>
            {(credentials.data ?? []).map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <button
            className="btn-secondary"
            onClick={() => createTarget.mutate()}
            disabled={createTarget.isPending || !targetName.trim() || !targetHosts.trim() || !targetPortListId}
          >
            {createTarget.isPending ? "Creando..." : "Guardar target"}
          </button>
        </div>
        {portLists.isError && (
          <p className="error-text">
            No se pudieron traer las listas de puertos de gvmd.{" "}
            <span className="error-detail">{connectionErrorDetail(portLists.error)}</span>
          </p>
        )}
        {createTarget.isError && (
          <p className="error-text">
            No se pudo crear el target.{" "}
            <span className="error-detail">{connectionErrorDetail(createTarget.error)}</span>
          </p>
        )}
        {targets.isError && (
          <p className="error-text">
            No se pudieron traer los targets de gvmd.{" "}
            <span className="error-detail">{connectionErrorDetail(targets.error)}</span>
          </p>
        )}

        {(targets.data ?? []).length > 0 && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Hosts</th>
                <th>Autenticado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(targets.data ?? []).map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td className="mono">{t.hosts}</td>
                  <td>{t.ssh_credential_id || t.smb_credential_id ? "si" : "no"}</td>
                  <td>
                    <button className="btn-link" onClick={() => deleteTarget.mutate(t.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {(targets.data ?? []).length === 0 && !targets.isError && (
          <p className="empty-hint">No hay targets guardados todavia.</p>
        )}
        {targetActionError != null && (
          <p className="error-text">
            No se pudo borrar el target.{" "}
            <span className="error-detail">{connectionErrorDetail(targetActionError)}</span>
          </p>
        )}
      </div>

      {/* --- Analisis y reportes --- */}
      <div className="panel">
        <h2>Analisis y reportes</h2>
        <p className="empty-hint">
          Tasks tal como los ve gvmd directamente (estado y progreso nativos de GVM). Los mismos analisis tambien
          aparecen enriquecidos con CVSS/EPSS/KEV en <Link to="/scans" className="btn-link">Escaneos</Link> y en{" "}
          <Link to="/vulnerabilities" className="btn-link">Vulnerabilidades</Link>.
        </p>
        {tasks.isError && (
          <p className="error-text">
            No se pudieron traer los analisis de gvmd.{" "}
            <span className="error-detail">{connectionErrorDetail(tasks.error)}</span>
          </p>
        )}
        {(tasks.data ?? []).length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Estado</th>
                <th>Progreso</th>
                <th>Reporte</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(tasks.data ?? []).map((t) => (
                <>
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td><TaskStatusBadge value={t.status} /></td>
                    <td>{t.progress}%</td>
                    <td>
                      {t.last_report_id ? (
                        <>
                          <button
                            className="btn-link"
                            onClick={() => setExpandedTaskId(expandedTaskId === t.id ? null : t.id)}
                          >
                            {expandedTaskId === t.id ? "Ocultar reporte" : "Ver reporte completo"}
                          </button>
                          {" "}
                          {EXPORT_FORMATS.map((f, idx) => (
                            <span key={f.value}>
                              {idx > 0 && " / "}
                              <button
                                className="btn-link"
                                onClick={() => t.last_report_id && handleExport(t.last_report_id, f.value)}
                              >
                                {f.label}
                              </button>
                            </span>
                          ))}
                        </>
                      ) : (
                        <span className="empty-hint">todavia sin reporte</span>
                      )}
                    </td>
                    <td></td>
                  </tr>
                  {expandedTaskId === t.id && (
                    <tr key={`${t.id}-expanded`}>
                      <td colSpan={5}>
                        {report.isLoading && <p className="empty-hint">Cargando reporte completo...</p>}
                        {report.isError && (
                          <p className="error-text">
                            No se pudo traer el reporte.{" "}
                            <span className="error-detail">{connectionErrorDetail(report.error)}</span>
                          </p>
                        )}
                        {report.data && (
                          <pre
                            className="mono"
                            style={{
                              maxHeight: 320,
                              overflow: "auto",
                              background: "rgba(0,0,0,0.25)",
                              padding: 12,
                              borderRadius: 6,
                              whiteSpace: "pre-wrap",
                              wordBreak: "break-word",
                            }}
                          >
                            {report.data.raw_xml}
                          </pre>
                        )}
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        ) : (
          !tasks.isError && <p className="empty-hint">Todavia no se lanzo ningun analisis de OpenVAS.</p>
        )}
        {exportError != null && (
          <p className="error-text">
            No se pudo exportar el reporte.{" "}
            <span className="error-detail">{connectionErrorDetail(exportError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
