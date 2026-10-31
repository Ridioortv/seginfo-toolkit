import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import PageHeader from "../components/PageHeader";
import { caseApi, reportApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import { connectionErrorDetail } from "../utils/errors";
import { saveBlob } from "../utils/download";
import {
  LEVEL_BADGE, LEVEL_LABEL, PERIODS, STATUS_BADGE, STATUS_HELP, STATUS_LABEL, changeText, fmtMsg, hoursText, sparkPoints, tone,
  type Delta, type ExecutiveSummary, type TrendPoint,
} from "../utils/executive";
import { currentLocale, t } from "../i18n";

function Kpi({ label, value, hint, delta, goodWhen }: { label: string; value: string | number; hint?: string; delta?: Delta; goodWhen?: "down" | "up" }) {
  const tn = delta && goodWhen ? tone(delta.change, goodWhen) : "neutral";
  return (
    <div className="stat-card">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {delta && (
        <span className="empty-hint" style={{ color: tn === "good" ? "var(--success)" : tn === "bad" ? "var(--danger)" : undefined }}>
          {changeText(delta)} {delta.change !== null && <>{t("vs periodo anterior")}</>}
        </span>
      )}
      {hint && <span className="empty-hint">{hint}</span>}
    </div>
  );
}

function Spark({ title, rows, field, color }: { title: string; rows: TrendPoint[]; field: keyof TrendPoint; color: string }) {
  const values = rows.map((r) => (r[field] as number | null) ?? null);
  const pts = sparkPoints(values, 220, 56);
  const last = [...values].reverse().find((v) => v !== null);
  return (
    <div>
      <div className="empty-hint">{title}</div>
      {pts ? (
        <svg viewBox="0 0 220 56" width="100%" height="56" role="img" aria-label={title}>
          <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
        </svg>
      ) : <div className="empty-hint" style={{ height: 56 }}>{t("Todavia no hay suficientes datos.")}</div>}
      <strong>{last ?? "-"}</strong>
    </div>
  );
}

const when = (ts: string) => new Date(ts).toLocaleDateString(currentLocale());

export default function Executive() {
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const canSign = role === "admin" || role === "soc_manager";
  const [days, setDays] = useState(30);
  const summary = useQuery({
    queryKey: ["exec-summary", days], refetchInterval: 5 * 60_000,
    queryFn: async () => (await caseApi.get<ExecutiveSummary>("/executive/summary", { params: { days } })).data,
  });
  const trend = useQuery({
    queryKey: ["exec-trend"], refetchInterval: 5 * 60_000,
    queryFn: async () => (await caseApi.get<{ items: TrendPoint[] }>("/executive/trend", { params: { days: 180 } })).data.items,
  });
  const download = useMutation({
    mutationFn: async (format: "zip" | "pdf") => {
      const resp = await reportApi.get<Blob>("/executive/pack", { params: { days, format }, responseType: "blob" });
      return saveBlob(resp, format === "zip" ? "informe-ejecutivo.zip" : "informe-ejecutivo.pdf");
    },
  });

  const s = summary.data;
  const v = s?.vulnerabilities, r = s?.remediation, x = s?.exposure, c = s?.compliance, k = s?.cases;
  const rows = trend.data ?? [];
  const maxScore = Math.max(1, ...(x?.by_business_unit ?? []).map((u) => u.score));
  return (
    <div>
      <PageHeader title="Tablero ejecutivo" subtitle="El estado de la seguridad en una pagina, comparado con el periodo anterior, para llevar a la direccion" />
      <div className="panel">
        <div className="gov-row-actions" style={{ marginTop: 0, alignItems: "center", flexWrap: "wrap" }}>
          <label className="empty-hint">{t("Periodo")}{" "}
            <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label={t("Periodo")}>
              {PERIODS.map((d) => <option key={d} value={d}>{t("Ultimos {0} dias", d)}</option>)}
            </select>
          </label>
          {canSign && (
            <>
              <button className="btn-primary" disabled={download.isPending} onClick={() => download.mutate("zip")}>
                {download.isPending ? t("Generando...") : t("Descargar informe firmado (PDF + prueba)")}
              </button>
              <button className="btn-secondary" disabled={download.isPending} onClick={() => download.mutate("pdf")}>{t("Solo el PDF")}</button>
            </>
          )}
        </div>
        {canSign && <p className="empty-hint">{t("Al descargar, TERO firma el informe y deja el hecho anotado en la cadena de custodia. El paquete incluye el verificador para comprobarlo sin TERO.")}</p>}
        {download.isSuccess && <p className="empty-hint">{t("Listo: se descargo {0}.", download.data)}</p>}
        {download.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(download.error)}</span></p>}
      </div>

      {summary.isLoading && <p className="empty-hint">Cargando...</p>}
      {summary.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(summary.error)}</span></p>}

      {s && (
        <>
          <div className="panel">
            <div className="gov-row-actions" style={{ marginTop: 0, alignItems: "center" }}>
              <span className={STATUS_BADGE[s.status]} style={{ fontSize: "1rem", padding: "6px 14px" }}>{t(STATUS_LABEL[s.status])}</span>
              <span>{t(STATUS_HELP[s.status])}</span>
            </div>
            <p className="empty-hint">{t("Periodo: {0} a {1}. Comparado con {2} a {3}.", when(s.period.from), when(s.period.to), when(s.previous_period.from), when(s.previous_period.to))}</p>
            <h3>{t("Que requiere atencion")}</h3>
            {s.attention.length === 0 && <p className="empty-hint">{t("Nada que requiera una decision en este periodo.")}</p>}
            {s.attention.length > 0 && (
              <table className="data-table">
                <tbody>
                  {s.attention.map((a) => (
                    <tr key={a.code}>
                      <td style={{ width: 110 }}><span className={LEVEL_BADGE[a.level]}>{t(LEVEL_LABEL[a.level])}</span></td>
                      <td>{fmtMsg(a.message)}</td>
                      <td style={{ width: 90 }}>{a.link && <Link to={a.link}>{t("Ver")}</Link>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="panel">
            <h3>{t("Indicadores clave")}</h3>
            <div className="cards-grid">
              {v && <Kpi label={t("Criticas y altas abiertas")} value={v.critical_high} hint={t("{0} abiertas en total", v.open_total)} />}
              {v && <Kpi label={t("Explotadas activamente (KEV)")} value={v.kev} hint={t("abiertas hoy")} />}
              {v && <Kpi label={t("Criticas o altas nuevas")} value={v.created_critical_high.current ?? 0} delta={v.created_critical_high} goodWhen="down" />}
              {v && <Kpi label={t("Criticas o altas corregidas")} value={v.remediated_critical_high.current ?? 0} delta={v.remediated_critical_high} goodWhen="up" />}
              {v && <Kpi label={t("La mas vieja sin corregir")} value={t("{0} dias", v.oldest_critical_high_days)} hint={t("critica o alta abierta")} />}
              {c && c.score_verified !== null && <Kpi label={t("Cumplimiento verificado")} value={`${c.score_verified}/100`} hint={c.change !== null ? t("{0} puntos vs periodo anterior", c.change > 0 ? `+${c.change}` : c.change) : t("sin comparacion")} />}
              {k && <Kpi label={t("Casos abiertos")} value={k.open} hint={t("{0} fuera de plazo", k.overdue)} />}
              {k && <Kpi label={t("Tiempo medio de resolucion de casos")} value={hoursText(k.mttr_hours.current)} delta={k.mttr_hours} goodWhen="down" />}
              {s.exceptions && <Kpi label={t("Excepciones de riesgo vigentes")} value={s.exceptions.active} hint={t("{0} por vencer", s.exceptions.expiring_soon)} />}
              {s.vendors && <Kpi label={t("Proveedores con riesgo alto o critico")} value={s.vendors.high_or_critical_risk} hint={t("{0} sin evaluacion vigente", s.vendors.without_assessment_critical_or_high)} />}
              {s.drills && <Kpi label={t("Simulacros de respuesta")} value={s.drills.completed_total} hint={s.drills.last_score !== null ? t("ultimo puntaje: {0}", s.drills.last_score) : t("ninguno todavia")} />}
              {s.custody && <Kpi label={t("Cadena de custodia")} value={s.custody.ok ? t("Integra") : t("Con problemas")} hint={t("{0} registros", s.custody.entries)} />}
            </div>
          </div>

          {r && (
            <div className="panel">
              <h3>{t("Tiempo de correccion: declarado vs real")}</h3>
              <div className="cards-grid">
                <Kpi label={t("Declarado")} value={hoursText(r.mttr_declared_hours)} hint={t("hasta que alguien marca la vulnerabilidad como corregida")} />
                <Kpi label={t("Real (cierre verificado)")} value={hoursText(r.mttr_real_hours)} hint={t("hasta que TERO comprueba con un nuevo escaneo que ya no esta")} />
                <Kpi label={t("Cierres que no pasaron la verificacion")} value={r.false_closure_rate_pct === null ? "-" : `${r.false_closure_rate_pct}%`} hint={t("{0} verificados, {1} fallidos", r.verified, r.failed)} />
                <Kpi label={t("Correcciones sin verificar")} value={r.remediated_unverified} hint={t("de {0} declaradas", r.remediated_total)} />
              </div>
              <p className="empty-hint">{t("La diferencia entre lo declarado y lo real es el tiempo que el riesgo siguio abierto sin que se supiera.")}</p>
            </div>
          )}

          {x && (
            <div className="panel">
              <h3>{t("Exposicion por unidad de negocio")}</h3>
              {x.units_defined === 0 && <div className="gov-callout gov-warn"><div>{t("Ningun activo tiene unidad de negocio asignada. Asignala en Activos para ver que area es responsable de cada exposicion.")} <Link to="/assets">{t("Ir a Activos")}</Link></div></div>}
              {x.by_business_unit.length === 0 ? <p className="empty-hint">{t("Todavia no hay activos ni vulnerabilidades abiertas.")}</p> : (
                <table className="data-table">
                  <thead><tr><th>{t("Unidad")}</th><th>{t("Activos")}</th><th>{t("Criticas")}</th><th>{t("Altas")}</th><th>KEV</th><th>{t("Exposicion")}</th><th style={{ width: "28%" }}>{t("% del total")}</th></tr></thead>
                  <tbody>
                    {x.by_business_unit.map((u) => (
                      <tr key={u.unit}>
                        <td>{u.unit.startsWith("(") ? t(u.unit) : u.unit}</td><td>{u.assets}</td><td>{u.critical}</td><td>{u.high}</td><td>{u.kev}</td><td>{u.score}</td>
                        <td>
                          <div style={{ background: "var(--bg-2)", borderRadius: 4, height: 10 }} aria-hidden>
                            <div style={{ width: `${Math.max(2, (u.score / maxScore) * 100)}%`, height: 10, borderRadius: 4, background: "var(--accent)" }} />
                          </div>
                          <span className="empty-hint">{u.share_pct}%</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p className="empty-hint">{t("Exposicion = vulnerabilidades abiertas ponderadas: critica {0}, alta {1}, media {2}, baja {3}; por 1,5 si se explota activamente. Es una ayuda para priorizar, no una medida de perdida economica.", x.weights.critical, x.weights.high, x.weights.medium, x.weights.low)}</p>
              {x.top_assets.length > 0 && (
                <>
                  <h3>{t("Activos con mayor exposicion")}</h3>
                  <table className="data-table">
                    <thead><tr><th>{t("Activo")}</th><th>{t("Unidad")}</th><th>{t("Criticas")}</th><th>{t("Altas")}</th><th>{t("Exposicion")}</th></tr></thead>
                    <tbody>
                      {x.top_assets.slice(0, 8).map((a) => (
                        <tr key={a.asset_id || "none"}><td>{a.hostname || t("(sin activo asociado)")}</td><td>{a.business_unit.startsWith("(") ? t(a.business_unit) : a.business_unit}</td><td>{a.critical}</td><td>{a.high}</td><td>{a.score}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          )}

          <div className="panel">
            <h3>{t("Tendencia")}</h3>
            {rows.length < 2 && <p className="empty-hint">{t("TERO guarda una foto de estos numeros por dia: la tendencia se va armando sola. Hoy hay {0}.", rows.length)}</p>}
            <div className="cards-grid">
              <Spark title={t("Criticas y altas abiertas")} rows={rows} field="critical_high" color="var(--danger)" />
              <Spark title={t("Cumplimiento verificado")} rows={rows} field="compliance" color="var(--success)" />
              <Spark title={t("Tiempo real de correccion (h)")} rows={rows} field="mttr_real_hours" color="var(--warning)" />
              <Spark title={t("Exposicion total")} rows={rows} field="exposure" color="var(--accent)" />
            </div>
          </div>

          {Object.entries(s.sources).some(([, f]) => !f.ok) && (
            <div className="gov-callout gov-warn"><div>{t("No se pudo leer: {0}. Esas secciones faltan; no se completan con ceros.", Object.entries(s.sources).filter(([, f]) => !f.ok).map(([n]) => n).join(", "))}</div></div>
          )}
        </>
      )}
    </div>
  );
}
