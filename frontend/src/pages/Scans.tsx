import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanApi } from "../services/api";
import type { ScanJobOut, ScanScheduleOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
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
type NetworkScope = "lan" | "man" | "wan" | "custom";

const SCOPE_LABELS: Record<NetworkScope, string> = {
  lan: "LAN (red local de la oficina/sede)",
  man: "MAN (enlace entre sedes/edificios)",
  wan: "WAN (internet / IPs publicas)",
  custom: "Personalizado",
};

// Rangos privados (RFC1918) mas comunes -- pensados como punto de partida
// para cubrir una red LAN tipica sin que el usuario tenga que saber de
// memoria la notacion CIDR. Siempre editable antes de lanzar el escaneo.
const LAN_PRESETS = ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"];

function scopeOf(job: ScanJobOut): string {
  const raw = job.options?.network_scope;
  return typeof raw === "string" && raw in SCOPE_LABELS ? raw : "-";
}

export default function Scans() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [scannerType, setScannerType] = useState<ScannerType>("nmap");
  const [scope, setScope] = useState<NetworkScope>("lan");
  const [targetsText, setTargetsText] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ ok: number; failed: number } | null>(null);

  const [schedName, setSchedName] = useState("");
  const [schedScannerType, setSchedScannerType] = useState<ScannerType>("nmap");
  const [schedTarget, setSchedTarget] = useState("");
  const [schedFrequency, setSchedFrequency] = useState<"daily" | "weekly">("daily");
  const [schedDayOfWeek, setSchedDayOfWeek] = useState(0);
  const [schedHour, setSchedHour] = useState(3);
  const [schedMinute, setSchedMinute] = useState(0);

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
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan-schedules"] }),
  });

  const deleteSchedule = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/scan-schedules/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan-schedules"] }),
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
            name: name || `Escaneo ${SCOPE_LABELS[scope]}`,
            scanner_type: scannerType,
            target,
            options: { network_scope: scope },
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
          Un escaneo por linea de destino. Acepta una IP suelta, un rango CIDR (ej. 192.168.1.0/24) o un hostname --
          usa el ambito para documentar si es red local, entre sedes o internet.
        </p>

        <div className="inline-form">
          <input placeholder="Nombre (opcional)" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={scannerType} onChange={(e) => setScannerType(e.target.value as ScannerType)}>
            <option value="nmap">nmap (descubrimiento de puertos/servicios)</option>
            <option value="trivy">trivy (imagenes/paquetes)</option>
            <option value="nuclei">nuclei (plantillas de deteccion)</option>
            <option value="openvas">openvas</option>
          </select>
          <select value={scope} onChange={(e) => setScope(e.target.value as NetworkScope)}>
            {Object.entries(SCOPE_LABELS).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </div>

        <textarea
          className="targets-textarea"
          placeholder={"192.168.1.0/24\n10.0.0.15\nvpn.tuempresa.com"}
          value={targetsText}
          onChange={(e) => setTargetsText(e.target.value)}
          rows={4}
          style={{ width: "100%", marginTop: 8, fontFamily: "monospace" }}
        />

        {scope === "lan" && (
          <button
            type="button"
            className="btn-secondary"
            style={{ marginTop: 8 }}
            onClick={() =>
              setTargetsText((prev) => {
                const existing = new Set(prev.split(/[\n,]/).map((t) => t.trim()).filter(Boolean));
                LAN_PRESETS.forEach((p) => existing.add(p));
                return Array.from(existing).join("\n");
              })
            }
          >
            + Agregar rangos privados comunes (para cubrir toda la LAN)
          </button>
        )}

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
        <h2>Escaneos programados</h2>
        <p className="empty-hint">
          Una regla corre solo mientras scan-service este arriba (usa su propio scheduler en proceso, sin
          infraestructura extra) -- si el contenedor se reinicia, las reglas habilitadas se vuelven a cargar solas
          al arrancar.
        </p>

        <div className="inline-form">
          <input placeholder="Nombre" value={schedName} onChange={(e) => setSchedName(e.target.value)} />
          <select value={schedScannerType} onChange={(e) => setSchedScannerType(e.target.value as ScannerType)}>
            <option value="nmap">nmap</option>
            <option value="trivy">trivy</option>
            <option value="nuclei">nuclei</option>
            <option value="openvas">openvas</option>
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
        {schedules.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(schedules.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
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
              </tr>
            </thead>
            <tbody>
              {scans.data.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td>{s.scanner_type}</td>
                  <td className="mono">{s.target}</td>
                  <td>{scopeOf(s)}</td>
                  <td>
                    <StatusBadge value={s.status} />
                    {s.error_message && (
                      <span className="error-detail">{s.error_message}</span>
                    )}
                  </td>
                  <td>{s.findings.length}</td>
                  <td>{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {scans.data.length === 0 && (
                <tr><td colSpan={7} className="empty-hint">Sin escaneos ejecutados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
