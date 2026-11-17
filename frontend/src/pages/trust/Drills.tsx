import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { caseApi, purpleApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { SeverityBadge } from "../../components/Badge";
import { connectionErrorDetail } from "../../utils/errors";
import { saveBlob } from "../../utils/download";
import {
  DRILL_STATUS_BADGE, DRILL_STATUS_LABEL, RATING_BADGE, RATING_LABEL, formatSeconds,
  type DrillScenarios, type DrillStats, type DrillView,
} from "../../utils/trust";
import { currentLocale, t } from "../../i18n";

const WRITERS = ["admin", "soc_manager"];
const READERS = ["admin", "soc_manager", "analyst"];

function when(ts: string | null | undefined): string {
  return ts ? new Date(ts).toLocaleString(currentLocale()) : "-";
}

function Step({ done, label, detail }: { done: boolean; label: string; detail?: string }) {
  return (
    <li>
      <span className={done ? "badge badge-success" : "badge badge-neutral"}>{done ? t("Listo") : t("Pendiente")}</span>{" "}
      {t(label)}{detail ? <span className="empty-hint"> {detail}</span> : null}
    </li>
  );
}

export default function Drills() {
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const canStart = WRITERS.includes(role);
  const canProof = READERS.includes(role);
  const [scenario, setScenario] = useState("phishing");
  const [, setTick] = useState(0);

  const scen = useQuery({ queryKey: ["drill-scenarios"], queryFn: async () => (await purpleApi.get<DrillScenarios>("/drills/scenarios")).data });
  const stats = useQuery({
    queryKey: ["drill-stats"], refetchInterval: 20_000,
    queryFn: async () => (await purpleApi.get<DrillStats>("/drills/stats")).data,
  });
  const list = useQuery({
    queryKey: ["drill-list"], refetchInterval: 10_000,
    queryFn: async () => (await purpleApi.get<DrillView[]>("/drills")).data,
  });
  const runningId = list.data?.find((d) => d.status === "running")?.id;
  const live = useQuery({
    queryKey: ["drill-live", runningId], enabled: Boolean(runningId), refetchInterval: 8_000,
    queryFn: async () => (await purpleApi.get<DrillView>(`/drills/${runningId}`)).data,
  });
  useEffect(() => { // el simulacro que estaba en curso termino: refresca historial y resumen
    if (live.data && live.data.status !== "running") {
      queryClient.invalidateQueries({ queryKey: ["drill-list"] });
      queryClient.invalidateQueries({ queryKey: ["drill-stats"] });
    }
  }, [live.data, queryClient]);
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, []);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["drill-list"] });
    queryClient.invalidateQueries({ queryKey: ["drill-stats"] });
    queryClient.invalidateQueries({ queryKey: ["drill-live"] });
  };
  const start = useMutation({
    mutationFn: async () => (await purpleApi.post<DrillView>("/drills", { scenario })).data,
    onSuccess: refresh,
  });
  const cancel = useMutation({
    mutationFn: async (id: string) => (await purpleApi.post(`/drills/${id}/cancel`)).data,
    onSuccess: refresh,
  });
  const proof = useMutation({
    mutationFn: async (id: string) =>
      saveBlob(await caseApi.get<Blob>(`/drills/${id}/attestation`, { responseType: "blob" }), "prueba-simulacro.json"),
  });

  const s = stats.data;
  const sc = scen.data;
  const current = live.data ?? list.data?.find((d) => d.status === "running");
  const selected = sc?.scenarios.find((x) => x.key === scenario);
  const finished = (list.data ?? []).filter((d) => d.status !== "running");
  const elapsed = current?.injected_at ? Math.max(0, (Date.now() - new Date(current.injected_at).getTime()) / 1000) : null;

  return (
    <div>
      <div className="panel">
        <h2>Simulacros de respuesta a incidentes</h2>
        <p className="empty-hint">
          Un simulacro pone en el SIEM un evento de ejemplo, rotulado como simulacro, y mide cuanto tarda tu equipo en reconocer la
          alerta y en cerrarla dejando una nota. El resultado es un puntaje de preparacion y una prueba firmada que se puede mostrar
          a un auditor o a una aseguradora.
        </p>
        <div className="gov-callout gov-ok">
          <strong>Es seguro:</strong>
          <div>
            No ejecuta ningun ataque, no toca ningun equipo y no dispara respuestas reales (no bloquea IP ni aisla equipos). Solo
            agrega una linea de registro de ejemplo y su alerta lleva la etiqueta SIMULACRO. Prueba que el camino evento a alerta
            funciona y, sobre todo, que las personas responden a tiempo.
          </div>
        </div>
        {stats.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(stats.error)}</span></p>}
        {s && (
          <div className="cards-grid">
            <div className="stat-card">
              <span className="stat-label">Preparacion</span>
              <span className="stat-value">{s.average_score_last5 === null ? "-" : `${s.average_score_last5}`}</span>
              <span className={RATING_BADGE[s.rating]}>{t(RATING_LABEL[s.rating])}</span>
            </div>
            <div className="stat-card"><span className="stat-label">Simulacros completados</span><span className="stat-value">{s.completed_total}</span></div>
            <div className="stat-card"><span className="stat-label">Dias desde el ultimo</span><span className="stat-value">{s.days_since_last === null ? "-" : Math.round(s.days_since_last)}</span></div>
            <div className="stat-card"><span className="stat-label">Tiempo mediano para reconocer</span><span className="stat-value">{formatSeconds(s.median_ack_seconds)}</span></div>
            <div className="stat-card"><span className="stat-label">Tiempo mediano para cerrar</span><span className="stat-value">{formatSeconds(s.median_close_seconds)}</span></div>
          </div>
        )}
      </div>

      {current ? (
        <div className="panel">
          <h2>Simulacro en curso: {t(current.title)}</h2>
          <p>{t(current.narrative)}</p>
          <div className="gov-callout gov-warn">
            <strong>Que tiene que hacer el equipo ahora:</strong>
            <div>Ir a SIEM, abrir la alerta marcada como simulacro, reconocerla y cerrarla con una nota de lo que se haria. El reloj ya corre.</div>
          </div>
          <ul>
            <Step done={Boolean(current.injected_at)} label="Evento de ejemplo enviado al SIEM" detail={when(current.injected_at)} />
            <Step done={current.result.detected} label="El SIEM creo la alerta" detail={current.result.detect_seconds !== null ? formatSeconds(current.result.detect_seconds) : undefined} />
            <Step done={Boolean(current.acked_at)} label="Alguien reconocio la alerta" detail={current.acked_at ? `${when(current.acked_at)} · ${formatSeconds(current.result.ack_seconds)}` : undefined} />
            <Step done={Boolean(current.closed_at)} label="La alerta se cerro con una nota" />
          </ul>
          {!current.result.detected && <p className="error-text">El SIEM no creo la alerta: hay un problema en el camino de deteccion. Anotalo, es un hallazgo del simulacro.</p>}
          <p className="empty-hint">
            {t("Pasos sugeridos:")} {current.steps.map((x) => t(x)).join(" · ")}
          </p>
          <p className="empty-hint">
            {elapsed !== null ? t("Tiempo transcurrido: {0}.", formatSeconds(elapsed)) : ""}{" "}
            {current.expires_at ? t("Vence el {0}.", when(current.expires_at)) : ""}
          </p>
          {current.last_error && <p className="error-text"><span className="error-detail">{current.last_error}</span></p>}
          {canStart && <button className="btn-secondary" disabled={cancel.isPending} onClick={() => cancel.mutate(current.id)}>Cancelar simulacro</button>}
          {cancel.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(cancel.error)}</span></p>}
        </div>
      ) : (
        <div className="panel">
          <h2>Empezar un simulacro</h2>
          {!canStart && <p className="empty-hint">Solo un administrador o un responsable del SOC puede empezar un simulacro.</p>}
          {sc && (
            <div className="cards-grid">
              {sc.scenarios.map((x) => (
                <label key={x.key} className="stat-card" style={{ cursor: canStart ? "pointer" : "default", outline: scenario === x.key ? "2px solid var(--accent, #6366f1)" : "none" }}>
                  <input type="radio" name="drill-scenario" value={x.key} checked={scenario === x.key} disabled={!canStart} onChange={() => setScenario(x.key)} />
                  <span className="stat-label">{t(x.title)}</span>
                  <SeverityBadge value={x.severity} />
                  <span className="empty-hint">{t(x.narrative)}</span>
                </label>
              ))}
            </div>
          )}
          {selected && <p className="empty-hint">{t("Pasos sugeridos:")} {selected.steps.map((x) => t(x)).join(" · ")}</p>}
          {canStart && <button className="btn-primary" disabled={start.isPending || !sc} onClick={() => start.mutate()}>Empezar simulacro</button>}
          {start.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(start.error)}</span></p>}
        </div>
      )}

      <div className="panel">
        <h2>Historial</h2>
        {list.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(list.error)}</span></p>}
        {list.isLoading && <p className="empty-hint">Cargando...</p>}
        {list.data && finished.length === 0 && <p className="empty-hint">Todavia no hay simulacros terminados.</p>}
        {proof.isSuccess && <p className="empty-hint">{t("Listo: se descargo {0}. Para verificarlo, ejecuta el verificador sobre ese archivo.", proof.data)}</p>}
        {proof.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(proof.error)}</span></p>}
        {finished.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead><tr><th>Fecha</th><th>Escenario</th><th>Estado</th><th>Puntaje</th><th>Reconocer</th><th>Cerrar</th><th></th></tr></thead>
              <tbody>
                {finished.map((d) => (
                  <tr key={d.id}>
                    <td>{when(d.completed_at ?? d.started_at)}</td>
                    <td>{t(d.title)}</td>
                    <td><span className={DRILL_STATUS_BADGE[d.status]}>{t(DRILL_STATUS_LABEL[d.status])}</span></td>
                    <td>
                      {d.score === null ? "-" : d.score}{" "}
                      <span className={RATING_BADGE[d.result.rating]}>{t(RATING_LABEL[d.result.rating])}</span>
                    </td>
                    <td>{formatSeconds(d.result.ack_seconds)}</td>
                    <td>{formatSeconds(d.result.close_seconds)}{d.result.close_seconds !== null && !d.result.note_ok ? ` (${t("sin nota")})` : ""}</td>
                    <td>{canProof && d.status !== "cancelled" && <button className="btn-link" disabled={proof.isPending} onClick={() => proof.mutate(d.id)}>Descargar prueba</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {sc && (
        <div className="panel">
          <h2>Como se puntua</h2>
          <ul>
            <li>{t("Deteccion: si el SIEM crea la alerta, {0} puntos.", sc.scoring.points.detect)}</li>
            <li>
              {t("Reconocer la alerta ({0} puntos como maximo):", sc.scoring.points.ack)}{" "}
              {sc.scoring.ack_bands.map(([limit, pts]) => t("hasta {0}: {1}", formatSeconds(limit), pts)).join(" · ")}
              {" · "}{t("mas tarde: {0}", sc.scoring.floors.ack)}
            </li>
            <li>
              {t("Cerrar con una nota ({0} puntos como maximo):", sc.scoring.points.close)}{" "}
              {sc.scoring.close_bands.map(([limit, pts]) => t("hasta {0}: {1}", formatSeconds(limit), pts)).join(" · ")}
              {" · "}{t("mas tarde: {0}", sc.scoring.floors.close)}
              {". "}{t("Sin una nota de al menos {0} letras, la mitad.", sc.scoring.min_note_chars)}
            </li>
            <li>{t("Si nadie la cierra en {0} horas, el simulacro vence y se puntua lo que paso.", sc.scoring.expire_hours)}</li>
          </ul>
          <p className="empty-hint">
            Preparado desde 80 puntos, parcial desde 50. El puntaje de preparacion es el promedio de los ultimos 5 simulacros. Los tiempos
            salen de la cadena de custodia, que no se puede alterar despues. Limite: el simulacro prueba el camino evento a alerta y la
            respuesta de las personas; no prueba las reglas de deteccion reales de tu organizacion (para eso esta la cobertura ATT&CK).
          </p>
        </div>
      )}
    </div>
  );
}
