import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { assetApi, scanApi } from "../services/api";
import type { AssetOut, ScanJobOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

type Environment = "production" | "staging" | "development" | "other";
type Criticality = "low" | "medium" | "high" | "critical";

const ENV_LABELS: Record<Environment, string> = {
  production: "Produccion",
  staging: "Staging",
  development: "Desarrollo",
  other: "Otro",
};

const CRITICALITY_LABELS: Record<Criticality, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Critica",
};

const ACTIVE_SCAN_STATUSES = new Set(["pending", "running"]);

const SCAN_STATUS_LABELS: Record<string, string> = {
  pending: "En cola...",
  running: "Escaneando...",
  completed: "Completado",
  failed: "Fallo",
  cancelled: "Cancelado",
  scanner_unavailable: "Scanner no disponible",
};

// Estado en vivo del escaneo lanzado desde la fila de un activo: sin esto el
// boton solo decia "lanzado" y despues no habia forma de saber si el escaneo
// termino, fallo o seguia corriendo (parecia que "no escaneaba").
function AssetScanStatus({ jobId }: { jobId: string }) {
  const job = useQuery({
    queryKey: ["asset-scan-job", jobId],
    queryFn: async () => (await scanApi.get<ScanJobOut>(`/scans/${jobId}`)).data,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !ACTIVE_SCAN_STATUSES.has(status) ? false : 3000;
    },
  });

  if (job.isError) {
    return (
      <p className="error-text" style={{ margin: "4px 0 0" }}>
        No se pudo consultar el estado del escaneo.{" "}
        <span className="error-detail">{connectionErrorDetail(job.error)}</span>
      </p>
    );
  }
  if (!job.data) return <p className="empty-hint" style={{ margin: "4px 0 0" }}>Consultando estado...</p>;

  const { status, findings, error_message: errorMessage } = job.data;
  const label = SCAN_STATUS_LABELS[status] ?? status;
  if (status === "completed") {
    return (
      <p className="empty-hint" style={{ margin: "4px 0 0" }}>
        {label}: {findings.length} hallazgo(s).{" "}
        <Link to="/vulnerabilities">Ver vulnerabilidades</Link> o el detalle en <Link to="/scans">Escaneos</Link>.
      </p>
    );
  }
  if (ACTIVE_SCAN_STATUSES.has(status)) {
    return <p className="empty-hint" style={{ margin: "4px 0 0" }}>{label}</p>;
  }
  return (
    <p className="error-text" style={{ margin: "4px 0 0" }}>
      {label}.{" "}
      {errorMessage && <span className="error-detail">{errorMessage}</span>}{" "}
      <Link to="/scans">Ver en Escaneos</Link>
    </p>
  );
}

export default function Assets() {
  const queryClient = useQueryClient();

  const [hostname, setHostname] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [osName, setOsName] = useState("");
  const [environment, setEnvironment] = useState<Environment>("production");
  const [criticality, setCriticality] = useState<Criticality>("medium");
  const [owner, setOwner] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const [scanFeedback, setScanFeedback] = useState<{ assetId: string; ok: boolean; message: string } | null>(null);
  // assetId -> id del ultimo escaneo lanzado desde la fila (para mostrar su estado en vivo).
  const [scanJobs, setScanJobs] = useState<Record<string, string>>({});

  const assets = useQuery({
    queryKey: ["assets"],
    queryFn: async () => (await assetApi.get<AssetOut[]>("/assets")).data,
  });

  const createAsset = useMutation({
    mutationFn: async () =>
      (
        await assetApi.post<AssetOut>("/assets", {
          hostname,
          ip_address: ipAddress,
          os_name: osName,
          environment,
          criticality,
          owner,
        })
      ).data,
    onSuccess: () => {
      setHostname("");
      setIpAddress("");
      setOsName("");
      setOwner("");
      setFormError(null);
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (err: unknown) => {
      setFormError(err instanceof Error ? err.message : "No se pudo agregar el activo.");
    },
  });

  const scanAsset = useMutation({
    mutationFn: async (asset: AssetOut) => {
      const target = asset.ip_address || asset.hostname;
      if (!target) {
        throw new Error("El activo no tiene IP ni hostname para escanear.");
      }
      return (
        await scanApi.post<ScanJobOut>("/scans", {
          name: `Escaneo de ${asset.hostname || asset.ip_address}`,
          scanner_type: "nuclei",
          target,
          asset_id: asset.id,
          options: { network_scope: "custom" },
        })
      ).data;
    },
    onSuccess: (job, asset) => {
      setScanJobs((prev) => ({ ...prev, [asset.id]: job.id }));
      setScanFeedback(null);
    },
    onError: (err: unknown, asset) => {
      // connectionErrorDetail trae el motivo real (HTTP 422 + detalle del
      // backend, sin respuesta, etc.) en vez del generico "Request failed
      // with status code 422".
      setScanFeedback({
        assetId: asset.id,
        ok: false,
        message: `No se pudo lanzar el escaneo. ${connectionErrorDetail(err)}`,
      });
    },
  });

  function onCreateAsset() {
    setFormError(null);
    if (!hostname.trim() && !ipAddress.trim()) {
      setFormError("Ingresa al menos un hostname o una IP.");
      return;
    }
    createAsset.mutate();
  }

  return (
    <div>
      <PageHeader title="Activos" subtitle="Inventario de activos monitoreados por la plataforma" />

      <div className="panel">
        <h2>Agregar activo para monitorear</h2>
        <p className="empty-hint">
          Registra un host, servidor o equipo de red. Una vez agregado, podes lanzar un escaneo de deteccion de
          fallos directamente desde la tabla de abajo.
        </p>
        <div className="inline-form">
          <input placeholder="Hostname (ej. srv-web-01)" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          <input
            className="mono"
            placeholder="IP (ej. 192.168.1.10)"
            value={ipAddress}
            onChange={(e) => setIpAddress(e.target.value)}
          />
          <input placeholder="Sistema operativo (opcional)" value={osName} onChange={(e) => setOsName(e.target.value)} />
        </div>
        <div className="inline-form" style={{ marginTop: 8 }}>
          <select value={environment} onChange={(e) => setEnvironment(e.target.value as Environment)}>
            {(Object.entries(ENV_LABELS) as [Environment, string][]).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          <select value={criticality} onChange={(e) => setCriticality(e.target.value as Criticality)}>
            {(Object.entries(CRITICALITY_LABELS) as [Criticality, string][]).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          <input placeholder="Owner / responsable (opcional)" value={owner} onChange={(e) => setOwner(e.target.value)} />
          <button
            className="btn-primary"
            onClick={onCreateAsset}
            disabled={createAsset.isPending}
          >
            {createAsset.isPending ? "Agregando..." : "Agregar activo"}
          </button>
        </div>
        {formError && <p className="error-text">{formError}</p>}
        {createAsset.isError && !formError && (
          <p className="error-text">
            No se pudo agregar el activo.{" "}
            <span className="error-detail">{connectionErrorDetail(createAsset.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        {assets.isLoading && <p className="empty-hint">Cargando...</p>}
        {assets.isError && (
          <p className="error-text">
            No se pudo conectar con asset-service.{" "}
            <span className="error-detail">{connectionErrorDetail(assets.error)}</span>
          </p>
        )}
        {assets.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP</th>
                <th>SO</th>
                <th>Entorno</th>
                <th>Criticidad</th>
                <th>Owner</th>
                <th>Activo</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {assets.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.hostname}</td>
                  <td className="mono">{a.ip_address}</td>
                  <td>{a.os_name} {a.os_version}</td>
                  <td>{a.environment}</td>
                  <td><SeverityBadge value={a.criticality} /></td>
                  <td>{a.owner}</td>
                  <td>{a.is_active ? "si" : "no"}</td>
                  <td>
                    <button
                      className="btn-link"
                      onClick={() => scanAsset.mutate(a)}
                      disabled={scanAsset.isPending && scanAsset.variables?.id === a.id}
                    >
                      {scanAsset.isPending && scanAsset.variables?.id === a.id ? "Escaneando..." : "Escanear (detectar fallos)"}
                    </button>
                    {scanFeedback && scanFeedback.assetId === a.id && (
                      <p className={scanFeedback.ok ? "empty-hint" : "error-text"} style={{ margin: "4px 0 0" }}>
                        {scanFeedback.message}
                      </p>
                    )}
                    {scanJobs[a.id] && <AssetScanStatus jobId={scanJobs[a.id]} />}
                  </td>
                </tr>
              ))}
              {assets.data.length === 0 && (
                <tr><td colSpan={8} className="empty-hint">Sin activos registrados todavia. Agrega uno arriba.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
