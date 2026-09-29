import { Fragment, useEffect, useState } from "react";
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
  OpenvasProgressOut,
  OpenvasAutoActivateRequest,
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

// Password GVM lista para copiar/usar sin escribir nada (ver panel "Activar
// OpenVAS" -- opcion "con contraseña elegida"). Mismo formato que
// secrets.token_urlsafe del orquestador (base64url sin padding).
function generateGvmPassword(): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
  // "" = corre en el servidor, sin agente (comportamiento historico, solo
  // WAN/internet). Si se elige un agente, la regla la ejecuta EL (misma
  // visibilidad de red que tenga esa maquina) -- ver ScanSchedule.agent_id.
  const [schedAgentId, setSchedAgentId] = useState("");
  const [schedAgentApiKey, setSchedAgentApiKey] = useState("");

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
  // Activacion automatica de OpenVAS (boton "Probar y activar" -> POST
  // /openvas/auto-activate, ver mas abajo). autoActivating controla el
  // polling de progreso; autoActivateResult guarda las credenciales a
  // mostrar una vez listo (se limpia solo al cerrar el panel).
  const [autoActivating, setAutoActivating] = useState(false);
  const [autoActivateResult, setAutoActivateResult] = useState<{ gvm_user: string; gvm_password: string } | null>(
    null,
  );
  // Nombre del campo copiado hace poco (para el "Copiado!" transitorio de
  // los botones "Copiar" de usuario/contraseña GVM).
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const copyToClipboard = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField((f) => (f === field ? null : f)), 1500);
    } catch {
      // Sin permiso/soporte de clipboard -- no rompas la UI por esto, el
      // valor sigue visible y seleccionable a mano (userSelect: "all").
    }
  };

  // Errores de acciones sobre filas ya existentes (togglear/borrar) --
  // separado de formError/createX.isError, que son solo para los
  // formularios de arriba de cada tabla.
  const [scheduleActionError, setScheduleActionError] = useState<unknown>(null);
  const [agentActionError, setAgentActionError] = useState<unknown>(null);
  const [scanActionError, setScanActionError] = useState<unknown>(null);
  const [scanCancelError, setScanCancelError] = useState<unknown>(null);
  const [agentScanActionError, setAgentScanActionError] = useState<unknown>(null);

  // Fila expandida (a lo sumo una por tabla) mostrando los resultados
  // completos del escaneo -- severidad, CVSS/EPSS/KEV y remediacion
  // sugerida, via ScanResultsPanel.
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [expandedAgentScanId, setExpandedAgentScanId] = useState<string | null>(null);

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: async () => (await scanApi.get<ScanJobOut[]>("/scans")).data,
    refetchInterval: 10_000,
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
          agent_id: schedAgentId || null,
          agent_api_key: schedAgentId ? schedAgentApiKey : null,
        })
      ).data,
    onSuccess: () => {
      setSchedName("");
      setSchedTarget("");
      setSchedAgentApiKey("");
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

  // Levanta OpenVAS de punta a punta (contenedores + feeds + usuario GVM)
  // via el sidecar openvas-orchestrator, sin que el operador toque
  // PowerShell -- ver POST /openvas/auto-activate en main.py.
  // Acepta overrides opcionales para el boton "Arrancar OpenVAS" (que
  // siempre manda admin + password vacio para que la genere el
  // orquestador, sin importar lo que haya en los campos de "con
  // contraseña elegida"); sin overrides, usa los campos tal cual estan.
  const autoActivateOpenvas = useMutation({
    mutationFn: async (overrides?: Partial<OpenvasAutoActivateRequest>) =>
      (
        await scanApi.post<OpenvasProgressOut>("/openvas/auto-activate", {
          gvm_user: ovUser.trim() || "admin",
          gvm_password: ovPassword,
          gvm_socket_path: ovSocket,
          ...overrides,
        })
      ).data,
    onSuccess: (data) => {
      setAutoActivateResult(null);
      setAutoActivating(true);
      queryClient.setQueryData(["openvas-progress"], data);
    },
  });

  // Polling del progreso mientras la activacion automatica esta en curso
  // -- ver GET /openvas/auto-activate/progress.
  const openvasProgress = useQuery({
    queryKey: ["openvas-progress"],
    queryFn: async () => (await scanApi.get<OpenvasProgressOut>("/openvas/auto-activate/progress")).data,
    enabled: autoActivating,
    refetchInterval: 3000,
    retry: false,
  });

  useEffect(() => {
    const data = openvasProgress.data;
    if (!data) return;
    if (data.ready) {
      setAutoActivating(false);
      setAutoActivateResult({ gvm_user: data.gvm_user ?? ovUser, gvm_password: data.gvm_password ?? "" });
      queryClient.setQueryData(["openvas-status"], { configured: true, ready: true, detail: data.detail });
    } else if (data.error) {
      setAutoActivating(false);
    } else if (!data.running) {
      // Estado idle inesperado (nunca se disparo /start) -- no sigas
      // consultando por las dudas.
      setAutoActivating(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openvasProgress.data]);

  // Al abrir el panel, precarga una contraseña GVM lista para copiar/usar
  // en la opcion "con contraseña elegida" -- asi el campo nunca aparece
  // vacio pidiendo que se le tipee algo (ver generateGvmPassword arriba).
  useEffect(() => {
    if (openvasPanelOpen && !openvasReady && !autoActivating && !autoActivateResult && !ovPassword) {
      setOvPassword(generateGvmPassword());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openvasPanelOpen]);

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
      setScanCancelError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => setScanCancelError(err),
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
          al arrancar. La hora es la zona horaria configurada en el servidor (variable SCHEDULER_TIMEZONE en .env,
          default UTC si no esta seteada) -- no necesariamente la hora de tu navegador.
        </p>

        {(() => {
          // Etiqueta + nota aparte para "Agente Docker": corre DENTRO de
          // Docker (mismo host que scan-service) asi que ve internet y el
          // host, pero no la LAN real -- a diferencia de "Agente LAN", que
          // corre fuera de Docker con visibilidad de red completa. Se arma
          // por nombre (mismo criterio que el aviso de "Agente LAN" caido
          // mas abajo, en "Agentes de escaneo remoto") en vez de un campo
          // nuevo en el modelo: no hace falta mas que distinguir estos dos
          // casos conocidos para mostrar la aclaracion correcta.
          const agentLabel = (a: ScanAgentOut) =>
            a.name.toLowerCase().includes("docker") ? `${a.name} (internet/host)` : a.name;
          const selectedAgent = (agents.data ?? []).find((a) => a.id === schedAgentId);
          return (
            <div className="panel" style={{ marginTop: 8, marginBottom: 8 }}>
              <h3 style={{ marginTop: 0 }}>Quien ejecuta el escaneo</h3>
              <p className="empty-hint">
                Sin agente, la regla corre DENTRO del contenedor de scan-service: nmap y nuclei siempre (trivy no
                escanea IPs/hosts, usa el panel de arriba) y openvas tambien si ya lo activaste (ver "Escaneos
                remotos" mas abajo) -- por el aislamiento de red de Docker Desktop, sin agente solo alcanza
                WAN/internet, nunca tu LAN real. Elegi{" "}
                <strong>Agente LAN</strong> para poder programar escaneos a tu red real (192.168.x.x, etc.) o{" "}
                <strong>Agente Docker</strong> para que lo ejecute el propio host Docker (internet/host, misma
                visibilidad que corriendo sin agente). La api key de estos dos se carga sola -- no hace falta
                pegarla. Para un agente registrado a mano hay que pegar su api key aca.
              </p>
              <div className="inline-form">
                <select
                  value={schedAgentId}
                  onChange={(e) => {
                    const id = e.target.value;
                    setSchedAgentId(id);
                    if (!id) {
                      // openvas sigue siendo una opcion valida sin agente
                      // (corre con el gvmd del propio scan-service, ver el
                      // <select> de scanner mas abajo) -- solo limpiamos la
                      // api key, que ya no aplica.
                      setSchedAgentApiKey("");
                      return;
                    }
                    // Autocompletado: la key de los agentes bootstrap
                    // (Agente LAN/Agente Docker) se resuelve sola desde
                    // BOOTSTRAP_AGENTS (ver ScanAgentOut.bootstrap_api_key)
                    // -- para un agente registrado a mano, bootstrap_api_key
                    // viene null y el campo de abajo pide la key.
                    const selected = (agents.data ?? []).find((a) => a.id === id);
                    setSchedAgentApiKey(selected?.bootstrap_api_key ?? "");
                  }}
                >
                  <option value="">Servidor (sin agente, WAN/internet)</option>
                  {(agents.data ?? []).map((a) => (
                    <option key={a.id} value={a.id}>{agentLabel(a)}</option>
                  ))}
                </select>
                {schedAgentId && !selectedAgent?.bootstrap_api_key && (
                  <input
                    type="password"
                    className="mono"
                    placeholder="Api key del agente"
                    value={schedAgentApiKey}
                    onChange={(e) => setSchedAgentApiKey(e.target.value)}
                    title="La api key que te mostro la UI al registrar el agente. Se valida contra el agente elegido antes de crear la regla; nunca se guarda."
                  />
                )}
              </div>
              {agents.data && agents.data.length === 0 && (
                <p className="empty-hint" style={{ marginTop: 8 }}>
                  No hay ningun agente registrado todavia (ver "Agentes de escaneo remoto" mas abajo).
                </p>
              )}
            </div>
          );
        })()}

        <div className="inline-form">
          <input placeholder="Nombre" value={schedName} onChange={(e) => setSchedName(e.target.value)} />
          <select value={schedScannerType} onChange={(e) => setSchedScannerType(e.target.value as ScannerType)}>
            <option value="nmap">nmap</option>
            <option value="nuclei">nuclei</option>
            {openvasReady && <option value="openvas">openvas (activo)</option>}
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
            disabled={createSchedule.isPending || !schedTarget.trim() || (!!schedAgentId && !schedAgentApiKey.trim())}
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
                <th>Agente</th>
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
                  <td>
                    {s.agent_id
                      ? (agents.data ?? []).find((a) => a.id === s.agent_id)?.name ?? "agente eliminado"
                      : "servidor (sin agente)"}
                  </td>
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
          {openvasReady && !autoActivateResult ? (
            <span className="empty-hint" style={{ color: "var(--success, #2f9e44)" }}>
              OpenVAS esta activo y disponible como scanner remoto.
            </span>
          ) : (
            <button type="button" className="btn-secondary" onClick={() => setOpenvasPanelOpen((v) => !v)}>
              {openvasPanelOpen ? "Cerrar" : "Activar OpenVAS"}
            </button>
          )}
        </div>

        {openvasPanelOpen && (!openvasReady || autoActivateResult) && (
          <div className="panel" style={{ marginBottom: 10, border: "1px solid #d9a900" }}>
            <h3 style={{ marginTop: 0 }}>Activar OpenVAS</h3>

            {autoActivateResult ? (
              <>
                <p className="empty-hint" style={{ color: "var(--success, #2f9e44)" }}>
                  OpenVAS quedo activo y listo para usarse.
                </p>
                <div
                  className="panel"
                  style={{ background: "var(--bg-2, #f6f6f6)", padding: 10, marginBottom: 8 }}
                >
                  <div className="inline-form" style={{ alignItems: "center" }}>
                    <span className="empty-hint">Usuario GVM:</span>
                    <code className="mono" style={{ userSelect: "all" }}>
                      {autoActivateResult.gvm_user}
                    </code>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => copyToClipboard(autoActivateResult.gvm_user, "result-user")}
                    >
                      {copiedField === "result-user" ? "Copiado!" : "Copiar"}
                    </button>
                  </div>
                  {autoActivateResult.gvm_password && (
                    <div className="inline-form" style={{ alignItems: "center", marginTop: 6 }}>
                      <span className="empty-hint">Contraseña GVM:</span>
                      <code className="mono" style={{ userSelect: "all" }}>
                        {autoActivateResult.gvm_password}
                      </code>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => copyToClipboard(autoActivateResult.gvm_password, "result-password")}
                      >
                        {copiedField === "result-password" ? "Copiado!" : "Copiar"}
                      </button>
                    </div>
                  )}
                </div>
                <p className="empty-hint">
                  Guardala si la necesitas despues -- ya quedo escrita en .env, asi que sobrevive un reinicio del
                  stack.
                </p>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => {
                    setAutoActivateResult(null);
                    setOpenvasPanelOpen(false);
                    setOvPassword("");
                  }}
                >
                  Cerrar
                </button>
              </>
            ) : autoActivating ? (
              <>
                <p className="empty-hint">
                  Levantando OpenVAS (contenedores, sincronizacion de feeds y usuario GVM) -- la primera vez puede
                  tardar 20-40 minutos por la sincronizacion de feeds. Podes navegar a otra pantalla, sigue
                  corriendo solo en el servidor.
                </p>
                <div
                  style={{
                    background: "var(--bg-2, #eee)",
                    borderRadius: 6,
                    overflow: "hidden",
                    height: 18,
                    marginTop: 8,
                  }}
                >
                  <div
                    style={{
                      width: `${Math.min(100, Math.max(3, openvasProgress.data?.percent ?? 3))}%`,
                      background: "var(--accent, #2f7dd9)",
                      height: "100%",
                      transition: "width 0.4s ease",
                    }}
                  />
                </div>
                <p className="empty-hint" style={{ marginTop: 6 }}>
                  {openvasProgress.data?.percent ?? 1}% -- {openvasProgress.data?.detail || "Iniciando..."}
                </p>
                {openvasProgress.isError && (
                  <p className="error-text">
                    No se pudo consultar el progreso.{" "}
                    <span className="error-detail">{connectionErrorDetail(openvasProgress.error)}</span>
                  </p>
                )}
              </>
            ) : (
              <>
                <p className="empty-hint">
                  OpenVAS es el escaner mas pesado (~16 contenedores extra, varios GB de feeds) y por eso arranca
                  apagado. Elegi una de las dos opciones -- ambas levantan todo solas (contenedores, sincronizacion
                  de feeds y usuario GVM), sin tocar nada mas. La primera vez puede tardar 20-40 minutos por la
                  sincronizacion de feeds.
                </p>

                <div className="panel" style={{ marginTop: 10, marginBottom: 10 }}>
                  <h4 style={{ marginTop: 0 }}>Opcion 1: arrancar directo</h4>
                  <p className="empty-hint">
                    Un solo click, no pide nada. La contraseña la genera el sistema sola y la mostramos aca (para
                    copiar) apenas termine.
                  </p>
                  <button
                    className="btn-primary"
                    onClick={() =>
                      autoActivateOpenvas.mutate({ gvm_user: "admin", gvm_password: "", gvm_socket_path: "" })
                    }
                    disabled={autoActivateOpenvas.isPending}
                  >
                    {autoActivateOpenvas.isPending ? "Iniciando..." : "Arrancar OpenVAS"}
                  </button>
                </div>

                <div className="panel" style={{ marginBottom: 10 }}>
                  <h4 style={{ marginTop: 0 }}>Opcion 2: con contraseña elegida</h4>
                  <p className="empty-hint">
                    Usuario y contraseña ya vienen cargados solos (los podes copiar o cambiar si querés algo
                    especifico) -- con un click arranca OpenVAS usando estos mismos.
                  </p>
                  <div className="inline-form" style={{ marginTop: 8, alignItems: "center" }}>
                    <input
                      placeholder="Usuario GVM"
                      value={ovUser}
                      onChange={(e) => setOvUser(e.target.value)}
                    />
                    <input
                      className="mono"
                      placeholder="Contraseña GVM"
                      value={ovPassword}
                      onChange={(e) => setOvPassword(e.target.value)}
                      style={{ minWidth: 220 }}
                    />
                    <button type="button" className="btn-secondary" onClick={() => copyToClipboard(ovPassword, "ov-password")}>
                      {copiedField === "ov-password" ? "Copiado!" : "Copiar"}
                    </button>
                    <button type="button" className="btn-secondary" onClick={() => setOvPassword(generateGvmPassword())}>
                      Generar otra
                    </button>
                  </div>
                  <div className="inline-form" style={{ marginTop: 8 }}>
                    <input
                      className="mono"
                      placeholder="Socket (opcional, default /run/gvmd/gvmd.sock)"
                      value={ovSocket}
                      onChange={(e) => setOvSocket(e.target.value)}
                    />
                    <button
                      className="btn-primary"
                      onClick={() => autoActivateOpenvas.mutate()}
                      disabled={autoActivateOpenvas.isPending || !ovUser.trim() || !ovPassword.trim()}
                    >
                      {autoActivateOpenvas.isPending ? "Iniciando..." : "Probar y activar"}
                    </button>
                  </div>
                </div>

                {autoActivateOpenvas.isError && (
                  <p className="error-text">
                    No se pudo iniciar la activacion de OpenVAS.{" "}
                    <span className="error-detail">{connectionErrorDetail(autoActivateOpenvas.error)}</span>
                  </p>
                )}

                <details style={{ marginTop: 12 }}>
                  <summary className="empty-hint" style={{ cursor: "pointer" }}>
                    Metodo manual (avanzado -- correr los scripts de PowerShell vos mismo)
                  </summary>
                  <div style={{ marginTop: 8 }}>
                    <ol className="empty-hint" style={{ paddingLeft: 20 }}>
                      <li>
                        Abri PowerShell en la carpeta del proyecto y corre:{" "}
                        <code className="mono" style={{ userSelect: "all" }}>
                          powershell -ExecutionPolicy Bypass -File openvas\Encender-OpenVAS.ps1
                        </code>
                      </li>
                      <li>
                        Espera 20-40 minutos (la primera vez) a que los feeds terminen de sincronizar. Se puede
                        chequear el progreso con <code className="mono">docker compose --profile openvas ps</code>.
                      </li>
                      <li>
                        Corre <code className="mono">openvas\Configurar-OpenVAS.ps1</code> (crea el usuario GVM y
                        muestra la contraseña generada) -- o si ya tenes usuario/contraseña de GVM, pegalos arriba y
                        usa el boton de abajo.
                      </li>
                    </ol>
                    <div className="inline-form">
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => activateOpenvas.mutate()}
                        disabled={activateOpenvas.isPending || !ovUser.trim() || !ovPassword.trim()}
                      >
                        {activateOpenvas.isPending ? "Probando conexion..." : "Probar conexion (sin orquestador)"}
                      </button>
                    </div>
                    {activateOpenvas.isError && (
                      <p className="error-text">
                        No se pudo activar OpenVAS.{" "}
                        <span className="error-detail">{connectionErrorDetail(activateOpenvas.error)}</span>
                      </p>
                    )}
                    <p className="empty-hint" style={{ marginTop: 8 }}>
                      Esto prueba la conexion GMP con las credenciales de arriba y las activa en memoria, sin pasar
                      por el orquestador ni tocar Docker. Para que quede guardado tambien despues de un reinicio,
                      corre Configurar-OpenVAS.ps1 (escribe las credenciales en .env). Para apagar todo:{" "}
                      <code className="mono">openvas\Apagar-OpenVAS.ps1</code>.
                    </p>
                  </div>
                </details>
              </>
            )}
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
        {scanCancelError != null && (
          <p className="error-text">
            No se pudo cancelar el escaneo -- probablemente ya termino (completed/failed) antes de que
            llegara el pedido de cancelacion.{" "}
            <span className="error-detail">{connectionErrorDetail(scanCancelError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
