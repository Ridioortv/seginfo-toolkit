import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { coderepoApi } from "../../services/api";
import Icon, { type IconName } from "../../components/Icon";
import { connectionErrorDetail } from "../../utils/errors";
import { formatPct, weeklyBars, type Metrics } from "../../utils/governance";
import { t } from "../../i18n";

function Card({ icon, tone, label, value, hint }: { icon: IconName; tone: string; label: string; value: string; hint?: string }) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="stat-icon"><Icon name={icon} /></div>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {hint && <span className="stat-hint">{hint}</span>}
    </div>
  );
}

const HOURS_KEY = "tero-gov-hours-per-ai-change";

function loadHours(): string {
  try {
    return window.localStorage.getItem(HOURS_KEY) ?? "";
  } catch {
    return "";
  }
}

// Tablero para direccion: cuanto codigo es de IA, si se reviso, que paso en la compuerta y cuantos
// hallazgos aparecen por cada 1000 lineas en codigo de IA vs humano. Todo sale del registro real.
export default function Overview({ goTo }: { goTo: (tab: "ledger") => void }) {
  const [days, setDays] = useState(30);
  const [hours, setHours] = useState(loadHours);
  const hoursNum = Math.max(0, Number(hours.replace(",", ".")) || 0);

  useEffect(() => {
    try {
      window.localStorage.setItem(HOURS_KEY, hours);
    } catch {
      /* sin almacenamiento: no pasa nada */
    }
  }, [hours]);

  const metrics = useQuery({
    queryKey: ["gov-metrics", days, hoursNum],
    queryFn: async () =>
      (await coderepoApi.get<Metrics>("/governance/metrics", { params: { days, hours_per_ai_change: hoursNum } })).data,
  });

  const m = metrics.data;
  const bars = weeklyBars(m?.weekly ?? []);

  return (
    <div>
      <div className="panel">
        <div className="inline-form">
          <label>
            Periodo{" "}
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={7}>Ultimos 7 dias</option>
              <option value={30}>Ultimos 30 dias</option>
              <option value={90}>Ultimos 90 dias</option>
              <option value={365}>Ultimo año</option>
            </select>
          </label>
          <label>
            Horas que ahorra cada cambio con IA (opcional){" "}
            <input
              inputMode="decimal"
              placeholder="0"
              value={hours}
              onChange={(e) => setHours(e.target.value)}
              style={{ maxWidth: 110 }}
            />
          </label>
        </div>
        <p className="empty-hint" style={{ marginBottom: 0 }}>
          Los numeros salen del registro real de cambios de tus repositorios conectados. El ahorro de horas es una
          estimacion que cargas vos: TERO no puede medirlo solo.
        </p>
      </div>

      {metrics.isLoading && <p className="empty-hint">Cargando...</p>}
      {metrics.isError && (
        <p className="error-text">
          No se pudo cargar el tablero. <span className="error-detail">{connectionErrorDetail(metrics.error)}</span>
        </p>
      )}

      {m && m.totals.changes === 0 && (
        <div className="gov-callout gov-warn">
          <strong>Todavia no hay cambios registrados.</strong> Conecta un repositorio en "Código y Repositorios" y
          escanealo: TERO lee su historial de git y arma el contador solo.
        </div>
      )}

      {m && (
        <>
          <div className="cards-grid">
            <Card icon="code" tone="tone-accent" label="Cambios registrados" value={String(m.totals.changes)}
              hint={t("{0} humanos · {1} con IA", m.totals.human, m.totals.ai_changes)} />
            <Card icon="bolt" tone="tone-info" label="Codigo escrito con IA" value={formatPct(m.totals.ai_share_pct)}
              hint={t("{0} de las lineas agregadas", formatPct(m.totals.ai_lines_share_pct))} />
            <Card icon="check" tone={m.review.coverage_pct >= 80 ? "tone-success" : "tone-warning"}
              label="Codigo con IA revisado por una persona" value={formatPct(m.review.coverage_pct)}
              hint={t("{0} de {1} cambios aprobados", m.review.ai_changes_approved, m.review.ai_changes_needing_review)} />
            <Card icon="shield" tone={m.gate.blocked > 0 ? "tone-danger" : "tone-success"}
              label="Cambios marcados por la compuerta" value={String(m.gate.blocked + m.gate.observed_fail)}
              hint={t("{0} bloqueados · {1} solo observados", m.gate.blocked, m.gate.observed_fail)} />
            <Card icon="bug" tone="tone-warning" label="Hallazgos cada 1000 lineas (IA)" value={String(m.findings.per_1000_lines_ai)}
              hint={t("Humano: {0} cada 1000 lineas", m.findings.per_1000_lines_human)} />
            <Card icon="lock" tone={m.ledger.entries > 0 ? "tone-success" : "tone-info"} label="Entradas en el registro auditable"
              value={String(m.ledger.entries)} hint={m.review.avg_review_hours != null ? t("Revision promedio: {0} h", m.review.avg_review_hours) : undefined} />
            {m.roi.estimated_hours_saved != null && (
              <Card icon="zap" tone="tone-success" label="Horas ahorradas (estimado)" value={String(m.roi.estimated_hours_saved)}
                hint={t("{0} h por cada cambio con IA", m.roi.hours_per_ai_change)} />
            )}
          </div>

          <div className="dash-grid">
            <div className="panel">
              <h2>Lineas agregadas por semana</h2>
              {bars.length === 0 ? (
                <p className="empty-hint">Sin datos en este periodo.</p>
              ) : (
                <>
                  <div className="gov-bars" role="img" aria-label="Lineas agregadas por semana, humano contra IA">
                    {bars.map((b) => (
                      <div className="gov-bar-col" key={b.week} title={t("{0} lineas", b.total)}>
                        <div className="gov-bar">
                          <div className="gov-bar-human" style={{ height: `${b.humanPct}%` }} />
                          <div className="gov-bar-ai" style={{ height: `${b.aiPct}%` }} />
                        </div>
                        <span className="gov-bar-label">{b.week.slice(5)}</span>
                      </div>
                    ))}
                  </div>
                  <div className="gov-legend">
                    <span><span className="gov-dot gov-bar-human" />Humano</span>
                    <span><span className="gov-dot gov-bar-ai" />IA (incluye mixto)</span>
                  </div>
                </>
              )}
            </div>
            <div className="panel">
              <h2>Herramientas de IA detectadas</h2>
              {m.tools.length === 0 ? (
                <p className="empty-hint">Todavia no se detecto ninguna herramienta.</p>
              ) : (
                <table className="data-table">
                  <thead><tr><th>Herramienta</th><th>Cambios</th></tr></thead>
                  <tbody>
                    {m.tools.map((x) => (
                      <tr key={x.tool}><td>{x.tool}</td><td>{x.changes}</td></tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="panel">
            <h2>Por repositorio</h2>
            {m.by_repo.length === 0 ? (
              <p className="empty-hint">Sin cambios en este periodo.</p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Repositorio</th><th>Cambios</th><th>Con IA</th><th>% IA</th><th>Lineas</th>
                    <th>Hallazgos</th><th>Marcados</th>
                  </tr>
                </thead>
                <tbody>
                  {m.by_repo.map((r) => (
                    <tr key={r.repo_target_id}>
                      <td>{r.repo}</td><td>{r.changes}</td><td>{r.ai_changes}</td><td>{formatPct(r.ai_share_pct)}</td>
                      <td>{r.lines_added}</td><td>{r.findings}</td><td>{r.blocked}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="gov-callout">
            <strong>Como se sabe que codigo es de IA:</strong> por las marcas que deja la herramienta en el commit
            (Co-Authored-By, AI-Origin, Generated with...) y por lo que declaren las personas. Un commit sin marcas
            cuenta como humano hasta que alguien lo declare; cada declaracion queda en el{" "}
            <button className="btn-link" onClick={() => goTo("ledger")}>registro auditable</button>.
          </div>
        </>
      )}
    </div>
  );
}
