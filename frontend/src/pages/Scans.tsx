import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanApi, vulnApi } from "../services/api";
import type {
  ScanJobOut,
  ScanScheduleOut,
  ScanAgentOut,
  ScanAgentCreated,
  AgentScanJobOut,
  VulnerabilityOut,
  OpenvasStatusOut,
} from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { RunningIndicator } from "../components/RunningIndicator";
import { connectionErrorDetail } from "../utils/errors";

const DAY_LABELS = ["Lunes", "Martes", "Miercoles", "Jueves", "Viernes", "Sabado", "Domingo"];

function scheduleWhen(s: ScanScheduleOut): string {
  const time = `${String(s.hour).padStart(2, "0")}:${String(s.minute).padStart(2, "0")}`;
  if (s.frequency === "weekly") {
    return `Todos los ${DAY_LABELS[s.day_of_week ?? 0]} a las ${time}`;
  }
  return `Todos los dias a las ${time}`;
}

type ScannerType = "nmap" | "trivy" | "nuclei" | "openvas";
type NmapMode = "fast" | "full";
type NetworkScope = "lan" | "man" | "wan" | "custom";

const SCOPE_LABELS: Record<NetworkScope, string> = {
  lan: "LAN (red local de la oficina/sede)",
  man: "MAN (enlace entre sedes/edificios)",
  wan: "WAN (internet / IPs publicas)",
  custom: "Personalizado",
};

const CANCELLABLE_STATUSES = new Set(["pending", "running"]);

function scopeOf(job: ScanJobOut): string {
  const raw = job.options?.network_scope;
  return typeof raw === "string" && raw in SCOPE_LABELS ? raw : "-";
}

function packageLine(v: VulnerabilityOut): string | null {
  if (!v.package) return null;
  let line = v.package;
  if (v.installed_version) line += ` (${v.installed_version}`;
  if (v.fixed_version) line += ` -> ${v.fixed_version}`;
  if (v.installed_version) line += ")";
  return line;
}

// Resultados enriquecidos (severidad, CVSS/EPSS/KEV, remediacion sugerida)
// de UN escaneo puntual -- vuln-service ya hace todo ese trabajo (ver
// pagina Vulnerabilidades); esto solo lo consulta filtrado por
// scan_job_id y lo muestra en el lugar donde el escaneo se lanzo, para no
// tener que ir a buscar "que encontro" a otra pagina. Componente separado
// para poder llamar useQuery solo cuando la fila esta expandida (nunca se
// monta si el escaneo no se abrio).
function ScanResultsPanel({
  scanJobId,
  status,
  errorMessage,
}: {
  scanJobId: string;
  status: string;
  errorMessage: string;
}) {
  const isCompleted = status === "completed";
  const isTerminalFailure = status === "failed" || status === "scanner_unavailable";
  const isCancelled = status === "cancelled";

  const results = useQuery({
    queryKey: ["scan-vulnerabilities", scanJobId],
    queryFn: async () =>
      (await vulnApi.get<VulnerabilityOut[]>("/vulnerabilities", { params: { scan_job_id: scanJobId } })).data,
    enabled: isCompleted,
  });

  if (isCancelled) {
    return <p className="empty-hint">Este escaneo fue cancelado -- no hay resultados.</p>;
  }
  if (isTerminalFailure) {
    return (
      <p className="error-text">
        El escaneo fallo, no hay resultados. <span className="error-detail">{errorMessage || "Sin detalle del error."}</span>
      </p>
    );
  }
  if (!isCompleted) {
    return <p className="empty-hint">El escaneo todavia esta en curso -- los resultados aparecen aca cuando termine.</p>;
  }
  if (results.isLoading) {
    return <p className="empty-hint">Cargando resultados...</p>;
  }
  if (results.isError) {
    return (
      <p className="error-text">
        No se pudo conectar con vuln-service para traer los resultados enriquecidos.{" "}
        <span className="error-detail">{connectionErrorDetail(results.error)}</span>
      </p>
    );
  }
  if (!results.data || results.data.length === 0) {
    return <p className="empty-hint">Este escaneo no encontro hallazgos.</p>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {results.data.map((v) => {
        const pkgLine = packageLine(v);
        return (
          <div key={v.id} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
            <div className="inline-form" style={{ alignItems: "center" }}>
              <SeverityBadge value={v.severity} />
              <strong>{v.title}</strong>
              {v.cve_id && <span className="mono">{v.cve_id}</span>}
            </div>
            {(pkgLine || v.port != null) && (
              <p className="empty-hint" style={{ marginTop: 4, marginBottom: 4 }}>
                {pkgLine && <>Paquete: {pkgLine}. </>}
                {v.port != null && <>Puerto: {v.port}{v.service && ` (${v.service})`}.</>}
              </p>
            )}
            {v.description && <p style={{ marginTop: 4, marginBottom: 4 }}>{v.description}</p>}
            <strong style={{ display: "block", marginTop: 6 }}>Remediacion sugerida:</strong>
            <ul style={{ marginTop: 4, marginBottom: 0 }}>
              {v.remediation_steps.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

export default function Scans() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [nmapMode, setNmapMode] = useState<NmapMode>("full");
  const [targetsText, setTargetsText] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ ok: number; failed: number } | null>(null);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadName, setUploadName] = useState("");

  const [schedName, setSchedName] = useState("");
  const [schedScannerType, setSchedScannerType] = useState<ScannerType>("nmap");
  const [schedTarget, setSchedTarget] = useState("");
  const [schedFrequency, setSchedFrequency] = useState<"daily" | "weekly">("daily");
  const [schedDayOfWeek, setSchedDayOfWeek] = useState(0);
  const [schedHour, setSchedHour] = useState(3);
  const [schedMinute, setSchedMinute] = useState(0);

  const [agentName, setAgentName] = useState("");
  const [justCreatedKey, setJustCreatedKey] = useState<{ agentName: string; apiKey: string } | null>(null);
  const [agentJobAgentId, setAgentJobAgentId] = useState("");
  const [agentJobScannerType, setAgentJobScannerType] = useState<ScannerType>("nmap");
  const [agentJobName, setAgentJobName] = useState("");
  const [agentJobTarget, setAgentJobTarget] = useState("");
  // Api key del agente elegido: se pide al lanzar (ademas del login) y el
  // backend la valida contra ese agente antes de crear el job.
  const [agentJobApiKey, setAgentJobApiKey] = useState("");

  // Panel de activacion de OpenVAS (ver GET/POST /openvas/*) -- pide
  // usuario/contraseña/socket de GVM y prueba la conexion antes de darlo
  // por activo.
  const [openvasPanelOpen, setOpenvasPanelOpen] = useState(false);
  const [ovUser, setOvUser] = useState("admin");
  const [ovPassword, setOvPassword] = useState("");
  const [ovSocket, setOvSocket] = useState("");

  // Errores de acciones sobre filas ya existentes (togglear/borrar) --
  // separado de formError/createX.isError, que son solo para los
  // formularios de arriba de cada tabla.
  const [scheduleActionError, setScheduleActionError] = useState<unknown>(null);
  const [agentActionError, setAgentActionError] = useState<unknown>(null);
  const [scanActionError, setScanActionError] = useState<unknown>(null);
  const [agentScanActionError, setAgentScanActionError] = useState<unknown>(null);

  // Fila expandida (a lo sumo una por tabla) mostrando los resultados
  // completos del escaneo -- severidad, CVSS/EPSS/KEV y remediacion
  // sugerida, via ScanResultsPanel.
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [expandedAgentScanId, setExpandedAgentScanId] = useState<string | null>(null);

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: async () => (await scanApi.get<ScanJobOut[]>("/scans")).data,
  });

  const schedules = useQuery({
    queryKey: ["scan-schedules"],
    queryFn: async () => (await scanApi.get<ScanScheduleOut[]>("/scan-schedules")).data,
  });

  const createSchedule = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<ScanScheduleOut>("/scan-schedules", {
          name: schedName,
          scanner_type: schedScannerType,
          target: schedTarget,
          frequency: schedFrequency,
          hour: schedHour,
          minute: schedMinute,
          day_of_week: schedFrequency === "weekly" ? schedDayOfWeek : null,
        })
      ).data,
    onSuccess: () => {
      setSchedName("");
      setSchedTarget("");
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
  });

  const toggleSchedule = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      (await scanApi.patch<ScanScheduleOut>(`/scan-schedules/${id}`, { enabled })).data,
    onSuccess: () => {
      setScheduleActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
    onError: (err: unknown) => setScheduleActionError(err),
  });

  const deleteSchedule = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/scan-schedules/${id}`),
    onSuccess: () => {
      setScheduleActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
    onError: (err: unknown) => setScheduleActionError(err),
  });

  const agents = useQuery({
    queryKey: ["scan-agents"],
    queryFn: async () => (await scanApi.get<ScanAgentOut[]>("/agents")).data,
  });

  const agentScans = useQuery({
    queryKey: ["agent-scans"],
    queryFn: async () => (await scanApi.get<AgentScanJobOut[]>("/agent-scans")).data,
    refetchInterval: 10_000, // los jobs de agente avanzan por polling del lado del agente, no en el momento
  });

  // Estado real de OpenVAS: a diferencia de /scanners/status (que solo
  // mira si gvm-cli esta instalado), esto prueba la conexion GMP con las
  // credenciales actuales. Poll cada 15s para que aparezca solo como
  // opcion en "Escaneos remotos" apenas se activa (o se caiga si el
  // stack GVM se apaga), sin tener que recargar la pagina.
  const openvasStatus = useQuery({
    queryKey: ["openvas-status"],
    queryFn: async () => (await scanApi.get<OpenvasStatusOut>("/openvas/status")).data,
    refetchInterval: 15_000,
    retry: false,
  });
  const openvasReady = openvasStatus.data?.ready ?? false;

  const activateOpenvas = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<OpenvasStatusOut>("/openvas/activate", {
          gvm_user: ovUser,
          gvm_password: ovPassword,
          gvm_socket_path: ovSocket,
        })
      ).data,
    onSuccess: (data) => {
      queryClient.setQueryData(["openvas-status"], data);
      if (data.ready) {
        setOpenvasPanelOpen(false);
        setOvPassword("");
      }
    },
  });

  const createAgent = useMutation({
    mutationFn: async () => (await scanApi.post<ScanAgentCreated>("/agents", { name: agentName })).data,
    onSuccess: (created) => {
      setJustCreatedKey({ agentName: created.name, apiKey: created.api_key });
      setAgentName("");
      queryClient.invalidateQueries({ queryKey: ["scan-agents"] });
    },
  });

  const deleteAgent = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/agents/${id}`),
    onSuccess: () => {
      setAgentActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scan-agents"] });
      queryClient.invalidateQueries({ queryKey: ["agent-scans"] });
    },
    onError: (err: unknown) => setAgentActionError(err),
  });

  const createAgentScan = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<AgentScanJobOut>("/agent-scans", {
          agent_id: agentJobAgentId,
          scanner_type: agentJobScannerType,
          name: agentJobName,
          target: agentJobTarget,
          api_key: agentJobApiKey,
        })
      ).data,
    onSuccess: () => {
      setAgentJobName("");
      setAgentJobTarget("");
      setAgentJobApiKey("");
      queryClient.invalidateQueries({ queryKey: ["agent-scans"] });
    },
  });

  const deleteScan = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/scans/${id}`),
    onSuccess: () => {
      setScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => setScanActionError(err),
  });

  const cancelScan = useMutation({
    mutationFn: async (id: string) => (await scanApi.post<ScanJobOut>(`/scans/${id}/cancel`)).data,
    onSuccess: () => {
      setScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => setScanActionError(err),
  });

  const deleteAgentScan = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/agent-scans/${id}`),
    onSuccess: () => {
      setAgentScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["agent-scans"] });
    },
    onError: (err: unknown) => setAgentScanActionError(err),
  });

  // Borrado masivo para limpiar la vista. Se borra fila por fila (best-effort):
  // si alguna falla, las demas igual se borran.
  const deleteAllAgentScans = useMutation({
    mutationFn: async () => {
      const jobs = agentScans.data ?? [];
      await Promise.allSettled(jobs.map((j) => scanApi.delete(`/agent-scans/${j.id}`)));
    },
    onSuccess: () => {
      setAgentScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["agent-scans"] });
    },
    onError: (err: unknown) => setAgentScanActionError(err),
  });

  const deleteAllScans = useMutation({
    mutationFn: async () => {
      const jobs = (scans.data ?? []).filter((s) => s.status !== "running");
      await Promise.allSettled(jobs.map((s) => scanApi.delete(`/scans/${s.id}`)));
    },
    onSuccess: () => {
      setScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => setScanActionError(err),
  });

  const uploadScan = useMutation({
    mutationFn: async () => {
      if (!uploadFile) throw new Error("Elegi un archivo primero.");
      const form = new FormData();
      form.append("file", uploadFile);
      form.append("name", uploadName);
      return (await scanApi.post<ScanJobOut>("/scans/upload", form)).data;
    },
    onSuccess: () => {
      setUploadFile(null);
      setUploadName("");
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const createScans = useMutation({
    mutationFn: async () => {
      const targets = targetsText
        .split(/[\n,]/)
        .map((t) => t.trim())
        .filter(Boolean);
      if (targets.length === 0) {
        throw new Error("Ingresa al menos una IP, rango CIDR o hostname.");
      }
      const results = await Promise.allSettled(
        targets.map((target) =>
          scanApi.post("/scans", {
            name: name || "Escaneo WAN (nmap)",
            scanner_type: "nmap",
            target,
            options: { network_scope: "wan", mode: nmapMode },
          })
        )
      );
      const ok = results.filter((r) => r.status === "fulfilled").length;
      const failed = results.length - ok;
      return { ok, failed };
    },
    onSuccess: (summary) => {
      setLastResult(summary);
      setFormError(null);
      if (summary.failed === 0) {
        setTargetsText("");
      }
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => {
      setFormError(err instanceof Error ? err.message : "No se pudo crear el escaneo.");
    },
  });

  return (
    <div>
      <PageHeader
        title="Escaneos"
        subtitle="Orquestacion de escaneres defensivos (Nmap/Trivy/Nuclei/OpenVAS) -- deteccion, nunca explotacion"
      />

      <div className="panel">
        <h2>Nuevo escaneo</h2>
        <p className="empty-hint">
          Nmap contra internet (WAN) -- la unica combinacion de este panel que corre de forma confiable desde
          dentro de Docker, sin que la NAT del contenedor la bloquee. Un escaneo por linea de destino: IP suelta,
          rango CIDR (ej. 203.0.113.0/24) o hostname/dominio publico. Para tu red local (LAN) usa{" "}
          <strong>"Escaneos remotos"</strong> mas abajo, con un agente.
        </p>

        <div className="inline-form">
          <input placeholder="Nombre (opcional)" value={name} onChange={(e) => setName(e.target.value)} />
          <select
            value={nmapMode}
            onChange={(e) => setNmapMode(e.target.value as NmapMode)}
            title="Rapido: sin scripts NSE, top-100 puertos, mas veloz. Completo: deteccion de version + scripts NSE seguros, mas lento y mas exhaustivo."
          >
            <option value="fast">nmap rapido (top-100 puertos, sin scripts, mas veloz)</option>
            <option value="full">nmap completo (deteccion + scripts seguros, mas lento)</option>
          </select>
        </div>

        <textarea
          className="targets-textarea"
          placeholder={"203.0.113.10\nvpn.tuempresa.com\nmiweb.com"}
          value={targetsText}
          onChange={(e) => setTargetsText(e.target.value)}
          rows={4}
          style={{ width: "100%", marginTop: 8, fontFamily: "monospace" }}
        />

        <div style={{ marginTop: 10 }}>
          <button
            className="btn-primary"
            onClick={() => createScans.mutate()}
            disabled={createScans.isPending || !targetsText.trim()}
          >
            {createScans.isPending ? "Creando..." : "Lanzar escaneo(s)"}
          </button>
        </div>

        {formError && <p className="error-text">{formError}</p>}
        {lastResult && !formError && (
          <p className={lastResult.failed > 0 ? "error-text" : "empty-hint"}>
            {lastResult.ok} escaneo(s) creado(s){lastResult.failed > 0 ? `, ${lastResult.failed} fallaron` : ""}.
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Escanear imagen o paquete con Trivy (subir archivo)</h2>
        <p className="empty-hint">
          Subi una <strong>imagen de contenedor</strong> exportada con{" "}
          <code className="mono">docker save nombre:tag -o imagen.tar</code> (archivo .tar), o un{" "}
          <strong>manifiesto de dependencias</strong> (requirements.txt, package-lock.json, pom.xml, go.sum...).
          El escaneo corre en background (puede tardar varios minutos con archivos grandes) y el resultado
          aparece abajo en "Escaneos realizados", con su propia barra de progreso mientras corre. Limite 600 MB.
        </p>
        <div className="inline-form">
          <input type="file" onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)} />
          <input placeholder="Nombre (opcional)" value={uploadName} onChange={(e) => setUploadName(e.target.value)} />
          <button
            className="btn-primary"
            onClick={() => uploadScan.mutate()}
            disabled={uploadScan.isPending || !uploadFile}
          >
            {uploadScan.isPending ? "Escaneando..." : "Subir y escanear con Trivy"}
          </button>
        </div>
        {uploadFile && (
          <p className="empty-hint">Archivo: {uploadFile.name} ({Math.round(uploadFile.size / 1024)} KB)</p>
        )}
        {uploadScan.isError && (
          <p className="error-text">
            No se pudo escanear el archivo.{" "}
            <span className="error-detail">{connectionErrorDetail(uploadScan.error)}</span>
          </p>
        )}
        {uploadScan.isSuccess && (
          <p className="empty-hint">
            Archivo subido -- trivy lo esta escaneando en background. Segui el progreso en "Escaneos realizados"
            mas abajo, o revisa el inventario completo de paquetes en{" "}
            <Link to="/scan-images">Imagenes y Paquetes</Link> cuando termine.
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos programados</h2>
        <p className="empty-hint">
          Una regla corre solo mientras scan-service este arriba (usa su propio scheduler en proceso, sin
          infraestructura extra) -- si el contenedor se reinicia, las reglas habilitadas se vuelven a cargar solas
          al arrancar. Solo nmap y nuclei estan disponibles aca: trivy no escanea IPs/hosts (solo imagenes o
          paquetes, usa el panel de arriba) y openvas esta apagado por defecto (activalo en "Escaneos remotos").
          La hora es la zona horaria configurada en el servidor (variable SCHEDULER_TIMEZONE en .env, default UTC
          si no esta seteada) -- no necesariamente la hora de tu navegador.
        </p>

        <div className="inline-form">
          <input placeholder="Nombre" value={schedName} onChange={(e) => setSchedName(e.target.value)} />
          <select value={schedScannerType} onChange={(e) => setSchedScannerType(e.target.value as ScannerType)}>
            <option value="nmap">nmap</option>
            <option value="nuclei">nuclei</option>
          </select>
          <input
            className="mono"
            placeholder="Target (IP, CIDR, host, imagen segun el scanner)"
            value={schedTarget}
            onChange={(e) => setSchedTarget(e.target.value)}
          />
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
            disabled={createSchedule.isPending || !schedTarget.trim()}
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
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Target</th>
                <th>Cuando</th>
                <th>Ultima corrida</th>
                <th>Habilitada</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {schedules.data.map((s) => (
                <tr key={s.id}>
                  <td>{s.name || "-"}</td>
                  <td>{s.scanner_type}</td>
                  <td className="mono">{s.target}</td>
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
        {scheduleActionError != null && (
          <p className="error-text">
            No se pudo actualizar la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(scheduleActionError)}</span>
          </p>
        )}
        {schedules.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(schedules.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Agentes de escaneo remoto</h2>
        <p className="empty-hint">
          Docker Desktop aisla a los contenedores detras de NAT: scan-service no llega a la LAN real de la
          oficina/cliente aunque este instalado ahi. Un agente (script Python liviano, ver carpeta remote-agent/ en
          la raiz del repo) corre FUERA de Docker -- en esta PC o en cualquier otra de la LAN -- y hace polling hacia
          este mismo puerto: no hace falta abrir ningun puerto de entrada. La api key se muestra UNA sola vez al
          registrar el agente.
        </p>

        <div className="inline-form">
          <input
            placeholder="Nombre del agente (ej. PC-oficina-recepcion)"
            value={agentName}
            onChange={(e) => setAgentName(e.target.value)}
          />
          <button
            className="btn-primary"
            onClick={() => createAgent.mutate()}
            disabled={createAgent.isPending || !agentName.trim()}
          >
            {createAgent.isPending ? "Registrando..." : "Registrar agente"}
          </button>
        </div>
        {createAgent.isError && (
          <p className="error-text">
            No se pudo registrar el agente.{" "}
            <span className="error-detail">{connectionErrorDetail(createAgent.error)}</span>
          </p>
        )}

        {justCreatedKey && (
          <div className="panel" style={{ marginTop: 8, border: "1px solid #d9a900" }}>
            <p>
              Agente <strong>{justCreatedKey.agentName}</strong> registrado. Copia esta api key ahora -- no se va a
              volver a mostrar (pegala en la variable <code className="mono">AGENT_API_KEY</code> al configurar
              remote-agent/agent.py en la maquina donde va a correr el agente):
            </p>
            <p className="mono" style={{ wordBreak: "break-all", userSelect: "all" }}>{justCreatedKey.apiKey}</p>
            <button className="btn-secondary" onClick={() => setJustCreatedKey(null)}>Ya la copie</button>
          </div>
        )}

        {agents.data && agents.data.length > 0 && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Registrado por</th>
                <th>Api key</th>
                <th>Ultima vez visto</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {agents.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}</td>
                  <td>{a.created_by || "-"}</td>
                  <td>
                    {a.bootstrap_api_key ? (
                      <span className="mono" style={{ wordBreak: "break-all", userSelect: "all" }}>
                        {a.bootstrap_api_key}
                      </span>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td>{a.last_seen_at ? new Date(a.last_seen_at).toLocaleString() : "nunca (todavia no hizo polling)"}</td>
                  <td>
                    {a.is_protected ? (
                      <span
                        style={{ color: "var(--text-muted, #8a93a6)" }}
                        title="Este agente se crea automaticamente al iniciar el servicio y no se puede eliminar para que los escaneres siempre funcionen."
                      >
                        Protegido
                      </span>
                    ) : (
                      <button className="btn-link" onClick={() => deleteAgent.mutate(a.id)}>Eliminar</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {agents.data && (() => {
          // "Agente LAN" es el unico que ve la red real (192.168.x.x, etc.)
          // -- si nunca hizo polling, o hace mucho que no aparece, lo mas
          // probable es que agente-lan.ps1 no este corriendo en ninguna PC
          // todavia. Se lo recordamos aca en vez de dejar que se entere
          // recien cuando un escaneo de LAN se quede pending.
          const lanAgent = agents.data.find((a) => a.is_protected && a.name.toLowerCase().includes("lan"));
          if (!lanAgent) return null;
          const lastSeenMs = lanAgent.last_seen_at ? new Date(lanAgent.last_seen_at).getTime() : null;
          const staleMs = 5 * 60 * 1000;
          const isStale = lastSeenMs == null || Date.now() - lastSeenMs > staleMs;
          if (!isStale) return null;
          return (
            <p style={{ color: "var(--warning)", marginTop: 8 }}>
              "{lanAgent.name}" {lastSeenMs == null ? "todavia no hizo polling" : "hace rato que no aparece"} --
              para escanear tu red real (192.168.x.x, etc.) necesitas tenerlo corriendo en una PC con
              visibilidad a esa red. Doble-clic en <code className="mono">remote-agent/Instalar-Agente-LAN.bat</code>{" "}
              en esa PC (una sola vez, no hace falta ser administrador) y queda andando solo de ahi en adelante,
              incluso despues de reiniciar Windows.
            </p>
          );
        })()}
        {agentActionError != null && (
          <p className="error-text">
            No se pudo eliminar el agente.{" "}
            <span className="error-detail">{connectionErrorDetail(agentActionError)}</span>
          </p>
        )}
        {agents.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(agents.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos remotos</h2>
        <p className="empty-hint">
          Elegi el scanner ({openvasReady ? "nmap / nuclei / openvas" : "nmap / nuclei"}), el agente y el target.
          El agente elegido se lleva el job en su siguiente polling y manda el resultado solo -- puede tardar unos
          segundos segun su intervalo de polling. Cada scanner necesita su binario instalado en la maquina del
          agente; si falta, el job vuelve con un error claro. Para lanzar tenes que pegar la api key del agente (la
          que te mostro al registrarlo): se valida contra ese agente antes de crear el escaneo.
        </p>

        <div className="inline-form" style={{ marginBottom: 10 }}>
          {openvasReady ? (
            <span className="empty-hint" style={{ color: "var(--success, #2f9e44)" }}>
              OpenVAS esta activo y disponible como scanner remoto.
            </span>
          ) : (
            <button type="button" className="btn-secondary" onClick={() => setOpenvasPanelOpen((v) => !v)}>
              {openvasPanelOpen ? "Cerrar" : "Activar OpenVAS"}
            </button>
          )}
        </div>

        {openvasPanelOpen && !openvasReady && (
          <div className="panel" style={{ marginBottom: 10, border: "1px solid #d9a900" }}>
            <h3 style={{ marginTop: 0 }}>Activar OpenVAS</h3>
            <p className="empty-hint">
              OpenVAS es el escaner mas pesado (~16 contenedores extra, varios GB de feeds) y por eso arranca
              apagado. Este backend no tiene acceso a Docker, asi que el primer paso hay que hacerlo desde
              PowerShell en la PC donde corre el stack:
            </p>
            <ol className="empty-hint" style={{ paddingLeft: 20 }}>
              <li>
                Abri PowerShell en la carpeta del proyecto y corre:{" "}
                <code className="mono" style={{ userSelect: "all" }}>
                  powershell -ExecutionPolicy Bypass -File openvas\Encender-OpenVAS.ps1
                </code>
              </li>
              <li>
                Espera 20-40 minutos (la primera vez) a que los feeds terminen de sincronizar. Se puede chequear el
                progreso con <code className="mono">docker compose --profile openvas ps</code>.
              </li>
              <li>
                Corre <code className="mono">openvas\Configurar-OpenVAS.ps1</code> (crea el usuario GVM y muestra la
                contraseña generada) -- o si ya tenes usuario/contraseña de GVM, pegalos aca abajo directamente.
              </li>
            </ol>
            <div className="inline-form" style={{ marginTop: 8 }}>
              <input placeholder="Usuario GVM" value={ovUser} onChange={(e) => setOvUser(e.target.value)} />
              <input
                type="password"
                className="mono"
                placeholder="Contraseña GVM"
                value={ovPassword}
                onChange={(e) => setOvPassword(e.target.value)}
              />
              <input
                className="mono"
                placeholder="Socket (opcional, default /run/gvmd/gvmd.sock)"
                value={ovSocket}
                onChange={(e) => setOvSocket(e.target.value)}
              />
              <button
                className="btn-primary"
                onClick={() => activateOpenvas.mutate()}
                disabled={activateOpenvas.isPending || !ovUser.trim() || !ovPassword.trim()}
              >
                {activateOpenvas.isPending ? "Probando conexion..." : "Probar y activar"}
              </button>
            </div>
            {activateOpenvas.isError && (
              <p className="error-text">
                No se pudo activar OpenVAS.{" "}
                <span className="error-detail">{connectionErrorDetail(activateOpenvas.error)}</span>
              </p>
            )}
            <p className="empty-hint" style={{ marginTop: 8 }}>
              Esto activa OpenVAS en memoria, sin reiniciar el contenedor. Para que quede guardado tambien despues
              de un reinicio, corre Configurar-OpenVAS.ps1 (escribe las credenciales en .env). Para apagarlo:{" "}
              <code className="mono">openvas\Apagar-OpenVAS.ps1</code>.
            </p>
          </div>
        )}

        {agents.data && agents.data.length === 0 && (
          <p className="empty-hint">No hay ningun agente registrado todavia (ver panel de arriba).</p>
        )}

        <div className="inline-form">
          <select
            value={agentJobAgentId}
            onChange={(e) => {
              const id = e.target.value;
              setAgentJobAgentId(id);
              // Los agentes bootstrap (Agente Docker/Agente LAN) nunca se
              // registran a mano, asi que su api key nunca se vio en la UI
              // hasta ahora -- el backend la resuelve desde BOOTSTRAP_AGENTS
              // (ver ScanAgentOut.bootstrap_api_key) y se autocompleta aca
              // para no obligar a ir a buscarla en el .env.
              const selected = (agents.data ?? []).find((a) => a.id === id);
              if (selected?.bootstrap_api_key) {
                setAgentJobApiKey(selected.bootstrap_api_key);
              }
            }}
          >
            <option value="">Elegir agente...</option>
            {(agents.data ?? []).map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
          <select
            value={agentJobScannerType}
            onChange={(e) => setAgentJobScannerType(e.target.value as ScannerType)}
            title="El binario del scanner elegido tiene que estar instalado en la maquina del agente."
          >
            <option value="nmap">nmap (puertos/servicios)</option>
            <option value="nuclei">nuclei (plantillas de deteccion)</option>
            {openvasReady && <option value="openvas">openvas (activo)</option>}
          </select>
          <input placeholder="Nombre (opcional)" value={agentJobName} onChange={(e) => setAgentJobName(e.target.value)} />
          <input
            className="mono"
            placeholder="Target (IP, CIDR, host visible desde el agente)"
            value={agentJobTarget}
            onChange={(e) => setAgentJobTarget(e.target.value)}
          />
          <input
            type="password"
            className="mono"
            placeholder="Api key del agente"
            value={agentJobApiKey}
            onChange={(e) => setAgentJobApiKey(e.target.value)}
            title="La api key que te mostro la UI al registrar el agente. Se valida contra el agente elegido antes de lanzar."
          />
          <button
            className="btn-primary"
            onClick={() => createAgentScan.mutate()}
            disabled={createAgentScan.isPending || !agentJobAgentId || !agentJobTarget.trim() || !agentJobApiKey.trim()}
          >
            {createAgentScan.isPending ? "Creando..." : "Lanzar escaneo remoto"}
          </button>
        </div>
        {createAgentScan.isError && (
          <p className="error-text">
            No se pudo crear el escaneo remoto.{" "}
            <span className="error-detail">{connectionErrorDetail(createAgentScan.error)}</span>
          </p>
        )}
        {(agentScans.data?.length ?? 0) > 0 && (
          <div style={{ marginTop: 8 }}>
            <button
              className="btn-secondary"
              disabled={deleteAllAgentScans.isPending}
              onClick={() => deleteAllAgentScans.mutate()}
            >
              {deleteAllAgentScans.isPending ? "Limpiando..." : "Limpiar todos los escaneos remotos"}
            </button>
          </div>
        )}

        {agentScans.data && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Agente</th>
                <th>Target</th>
                <th>Estado</th>
                <th>Hallazgos</th>
                <th>Creado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {agentScans.data.map((j) => (
                <Fragment key={j.id}>
                  <tr>
                    <td>{j.name || "-"}</td>
                    <td>{(agents.data ?? []).find((a) => a.id === j.agent_id)?.name ?? j.agent_id}</td>
                    <td className="mono">{j.target}</td>
                    <td>
                      <StatusBadge value={j.status} />
                      {j.error_message && <span className="error-detail">{j.error_message}</span>}
                      {(j.status === "pending" || j.status === "assigned") && (
                        <RunningIndicator
                          since={j.assigned_at ?? j.created_at}
                          label={j.status === "pending" ? "en cola" : `${j.scanner_type} corriendo`}
                        />
                      )}
                    </td>
                    <td>{j.findings.length}</td>
                    <td>{new Date(j.created_at).toLocaleString()}</td>
                    <td>
                      <button
                        className="btn-link"
                        onClick={() => setExpandedAgentScanId(expandedAgentScanId === j.id ? null : j.id)}
                      >
                        {expandedAgentScanId === j.id ? "Ocultar resultados" : "Ver resultados"}
                      </button>
                      <button className="btn-link" onClick={() => deleteAgentScan.mutate(j.id)}>Eliminar</button>
                    </td>
                  </tr>
                  {expandedAgentScanId === j.id && (
                    <tr key={`${j.id}-detail`}>
                      <td colSpan={7} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
                        <ScanResultsPanel scanJobId={j.id} status={j.status} errorMessage={j.error_message} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {agentScans.data.length === 0 && (
                <tr><td colSpan={7} className="empty-hint">Sin escaneos remotos todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {agentScanActionError != null && (
          <p className="error-text">
            No se pudo eliminar el escaneo remoto.{" "}
            <span className="error-detail">{connectionErrorDetail(agentScanActionError)}</span>
          </p>
        )}
        {agentScans.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(agentScans.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos realizados</h2>
        {(scans.data?.length ?? 0) > 0 && (
          <div style={{ marginBottom: 8 }}>
            <button
              className="btn-secondary"
              disabled={deleteAllScans.isPending}
              onClick={() => deleteAllScans.mutate()}
            >
              {deleteAllScans.isPending ? "Limpiando..." : "Limpiar escaneos (menos los en curso)"}
            </button>
          </div>
        )}
        {scans.isLoading && <p className="empty-hint">Cargando...</p>}
        {scans.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(scans.error)}</span>
          </p>
        )}
        {scans.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Target</th>
                <th>Ambito</th>
                <th>Estado</th>
                <th>Hallazgos</th>
                <th>Creado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.data.map((s) => (
                <Fragment key={s.id}>
                  <tr>
                    <td>{s.name}</td>
                    <td>{s.scanner_type}</td>
                    <td className="mono">{s.target}</td>
                    <td>{scopeOf(s)}</td>
                    <td>
                      <StatusBadge value={s.status} />
                      {s.error_message && (
                        <span className="error-detail">{s.error_message}</span>
                      )}
                      {(s.status === "pending" || s.status === "running") && (
                        <RunningIndicator
                          since={s.started_at ?? s.created_at}
                          label={s.status === "pending" ? "en cola" : `${s.scanner_type} corriendo`}
                        />
                      )}
                    </td>
                    <td>{s.findings.length}</td>
                    <td>{new Date(s.created_at).toLocaleString()}</td>
                    <td>
                      <button className="btn-link" onClick={() => setExpandedScanId(expandedScanId === s.id ? null : s.id)}>
                        {expandedScanId === s.id ? "Ocultar resultados" : "Ver resultados"}
                      </button>
                      {CANCELLABLE_STATUSES.has(s.status) && (
                        <button
                          className="btn-link"
                          disabled={cancelScan.isPending}
                          onClick={() => cancelScan.mutate(s.id)}
                        >
                          Cancelar
                        </button>
                      )}
                      {s.status !== "running" && (
                        <button className="btn-link" onClick={() => deleteScan.mutate(s.id)}>Eliminar</button>
                      )}
                    </td>
                  </tr>
                  {expandedScanId === s.id && (
                    <tr key={`${s.id}-detail`}>
                      <td colSpan={8} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
                        <ScanResultsPanel scanJobId={s.id} status={s.status} errorMessage={s.error_message} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {scans.data.length === 0 && (
                <tr><td colSpan={8} className="empty-hint">Sin escaneos ejecutados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {scanActionError != null && (
          <p className="error-text">
            No se pudo eliminar el escaneo.{" "}
            <span className="error-detail">{connectionErrorDetail(scanActionError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
