import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { siemApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { connectionErrorDetail } from "../../utils/errors";
import {
  CHANNEL_LABEL, OUTCOME_LABEL, campaignTarget, sumCounts, vercelEnvBlock,
  type AntiEstafaStatus,
} from "../../utils/antiestafa";
import { currentLocale, t } from "../../i18n";

const MANAGERS = ["admin", "soc_manager"];

function when(ts: string | null | undefined): string {
  return ts ? new Date(ts).toLocaleString(currentLocale()) : "-";
}

export default function AntiEstafa() {
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const canSetup = MANAGERS.includes(role);
  const isAdmin = role === "admin";
  const [publicUrl, setPublicUrl] = useState("");
  const [token, setToken] = useState("");
  const [copied, setCopied] = useState(false);

  const status = useQuery({
    queryKey: ["antiestafa-status"], refetchInterval: 30_000,
    queryFn: async () => (await siemApi.get<AntiEstafaStatus>("/integrations/antiestafa/status")).data,
  });
  const setup = useMutation({
    mutationFn: async () => (await siemApi.post<{ created: string[]; status: AntiEstafaStatus }>("/integrations/antiestafa/setup")).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["antiestafa-status"] }),
  });
  const reveal = useMutation({
    mutationFn: async () => (await siemApi.get<{ token: string }>("/logs/ingest-token")).data.token,
    onSuccess: (value) => setToken(value),
  });

  const s = status.data;
  const block = s ? vercelEnvBlock(publicUrl, token, s.organization_id, s.ingest_path) : "";
  const allActive = s ? s.rules.active === s.rules.expected : false;

  async function copy() {
    try {
      await navigator.clipboard.writeText(block);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="panel">
      <h2>AntiEstafa AR: estafas que revisan las personas</h2>
      <p className="empty-hint">
        TERO cuida los equipos, los servidores y la red. AntiEstafa cubre lo que le llega a las personas: el WhatsApp falso del gerente, el audio
        del banco, el link de un proveedor trucho. Cuando un empleado revisa algo y da estafa o sospechoso, AntiEstafa avisa a TERO: se abre una
        alerta, se avisa al equipo y se abre un caso. Por defecto no se manda el texto del mensaje ni lo que dice el audio.
      </p>
      {status.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(status.error)}</span></p>}
      {s && (
        <>
          <div className="cards-grid">
            <div className="stat-card">
              <span className="stat-label">Reglas activas</span>
              <span className="stat-value">{s.rules.active} / {s.rules.expected}</span>
              <span className={allActive ? "badge badge-success" : "badge badge-medium"}>{allActive ? t("Listas") : t("Faltan reglas")}</span>
            </div>
            <div className="stat-card"><span className="stat-label">Avisos de los ultimos 7 dias</span><span className="stat-value">{s.reports}</span></div>
            <div className="stat-card"><span className="stat-label">Estafas</span><span className="stat-value">{s.by_outcome.estafa ?? 0}</span></div>
            <div className="stat-card"><span className="stat-label">Sospechosos</span><span className="stat-value">{s.by_outcome.sospechoso ?? 0}</span></div>
            <div className="stat-card"><span className="stat-label">Ultimo aviso</span><span className="stat-value" style={{ fontSize: "1rem" }}>{when(s.last_report_at)}</span></div>
          </div>
          {s.last_received && (
            <p className="empty-hint">
              {s.last_received.test
                ? t("Conexion comprobada: TERO recibio un evento de prueba el {0}.", when(s.last_received.at))
                : t("Ultimo evento recibido de AntiEstafa: {0}.", when(s.last_received.at))}
            </p>
          )}
          {canSetup && !allActive && (
            <div style={{ marginBottom: 12 }}>
              <button className="btn-primary" disabled={setup.isPending} onClick={() => setup.mutate()}>Activar las reglas de AntiEstafa</button>
              <span className="empty-hint"> {t("Faltan {0} regla(s). No duplica las que ya existen.", s.rules.missing.length)}</span>
            </div>
          )}
          {setup.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(setup.error)}</span></p>}
          {!canSetup && !allActive && <p className="empty-hint">Un administrador o un responsable del SOC tiene que activar las reglas.</p>}

          {s.campaigns.length > 0 && (
            <div className="gov-callout gov-warn">
              <strong>Campanas en curso:</strong>
              <ul>
                {s.campaigns.map((c, i) => {
                  const tg = campaignTarget(c.key);
                  return (
                    <li key={`${c.key}-${i}`}>
                      {tg.kind === "dominio"
                        ? t("El dominio {0} fue reportado {1} veces. Conviene avisar a todo el personal.", tg.value, c.reports)
                        : t("El mismo mensaje fue reportado {0} veces. Conviene avisar a todo el personal.", c.reports)}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {sumCounts(s.by_channel) > 0 && (
            <p className="empty-hint">
              {t("Por canal:")} {Object.entries(s.by_channel).map(([k, n]) => `${t(CHANNEL_LABEL[k] ?? k)}: ${n}`).join(" · ")}
              {" · "}{t("Resultado:")} {Object.entries(s.by_outcome).map(([k, n]) => `${t(OUTCOME_LABEL[k] ?? k)}: ${n}`).join(" · ")}
            </p>
          )}
          {s.top_domains.length > 0 && (
            <table className="data-table">
              <thead><tr><th>Dominio reportado</th><th>Veces</th></tr></thead>
              <tbody>{s.top_domains.map((d) => <tr key={d.domain}><td className="mono">{d.domain}</td><td>{d.count}</td></tr>)}</tbody>
            </table>
          )}
          {s.reports === 0 && <p className="empty-hint">Todavia no llego ningun aviso en los ultimos 7 dias.</p>}

          <h3 style={{ marginTop: 16 }}>Como conectarlo</h3>
          <ol>
            <li>Publica el SIEM de TERO con HTTPS solo para la ruta de AntiEstafa (la guia tiene un ejemplo). Los puertos de TERO quedan en la propia PC.</li>
            <li>{t("Escribe aca la direccion publica (sin la ruta {0}):", s.ingest_path)}</li>
          </ol>
          <div className="inline-form">
            <input style={{ flex: 2 }} placeholder="https://tero.tu-empresa.com.ar/api/siem" value={publicUrl} onChange={(e) => setPublicUrl(e.target.value)} />
            {isAdmin && <button className="btn-secondary" disabled={reveal.isPending} onClick={() => reveal.mutate()}>{token ? "Token mostrado" : "Mostrar el token"}</button>}
          </div>
          {reveal.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(reveal.error)}</span></p>}
          {!isAdmin && <p className="empty-hint">El token de ingesta lo muestra un administrador.</p>}
          <p className="empty-hint">Copia estas variables en el proyecto de Vercel de esa empresa y proba con el comando npm run tero:prueba.</p>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}>{block}</pre>
          <button className="btn-secondary" onClick={copy}>{copied ? "Copiado" : "Copiar variables"}</button>
          <p className="empty-hint">
            El token solo sirve para esta organizacion. Tratalo como una contrasena: no lo pegues en chats ni en repositorios.
          </p>
        </>
      )}
    </div>
  );
}
