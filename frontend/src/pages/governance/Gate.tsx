import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { coderepoApi } from "../../services/api";
import { connectionErrorDetail } from "../../utils/errors";
import {
  GATE_REASON_LABEL, TRIGGER_LABEL, buildCiWorkflow, shortSha, type GateRunOut,
} from "../../utils/governance";
import { currentLocale } from "../../i18n";
import type { RepoTargetOut } from "../../types";
import { GateBadge } from "./Provenance";

export default function Gate() {
  const [status, setStatus] = useState("");
  const [repoId, setRepoId] = useState("");
  const [copied, setCopied] = useState(false);

  const repos = useQuery({
    queryKey: ["code-repos"],
    queryFn: async () => (await coderepoApi.get<RepoTargetOut[]>("/repos")).data,
  });
  const runs = useQuery({
    queryKey: ["gov-runs", status],
    queryFn: async () =>
      (await coderepoApi.get<GateRunOut[]>("/governance/gate/runs", { params: { limit: 100, ...(status ? { status } : {}) } })).data,
  });

  const apiBase = (coderepoApi.defaults.baseURL ?? "").replace(/\/$/, "") || "https://TU-SERVIDOR-TERO:8015";
  const selectedRepo = repoId || repos.data?.[0]?.id || "ID-DEL-REPOSITORIO";
  const workflow = buildCiWorkflow(apiBase, selectedRepo);

  async function copy() {
    try {
      await navigator.clipboard.writeText(workflow);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div>
      <div className="panel">
        <h2>Compuerta de seguridad</h2>
        <p className="empty-hint">
          Cada cambio se revisa solo, antes de darlo por bueno: busca secretos, patrones inseguros (eval, shell=True,
          SQL armado con texto, TLS desactivado...), verifica si el codigo con IA tiene la revision humana que pide la
          politica, y decide: <strong>Aprobado</strong>, <strong>Bloqueado</strong> (politica en modo Exigir) o{" "}
          <strong>Hubiera bloqueado</strong> (modo Observar: avisa pero deja pasar). Se evalua al escanear un
          repositorio, al revisar o declarar un cambio, y cuando tu pipeline de CI lo consulta.
        </p>
      </div>

      <div className="panel">
        <h2>Ultimas evaluaciones</h2>
        <div className="inline-form">
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Todos los resultados</option>
            <option value="passed">Aprobado</option>
            <option value="blocked">Bloqueado</option>
            <option value="observed_fail">Hubiera bloqueado</option>
          </select>
        </div>
        {runs.isLoading && <p className="empty-hint">Cargando...</p>}
        {runs.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(runs.error)}</span></p>}
        {runs.data && runs.data.length === 0 && <p className="empty-hint">Todavia no hay evaluaciones.</p>}
        {runs.data && runs.data.length > 0 && (
          <table className="data-table">
            <thead>
              <tr><th>Fecha</th><th>Repositorio</th><th>Commit</th><th>Resultado</th><th>Politica</th><th>Disparada por</th><th>Motivos</th></tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id}>
                  <td>{new Date(r.created_at).toLocaleString(currentLocale())}</td>
                  <td>{r.repo_name}</td>
                  <td className="mono">{shortSha(r.commit_sha)}</td>
                  <td><GateBadge value={r.status} /></td>
                  <td>{r.policy_name}</td>
                  <td>{TRIGGER_LABEL[r.trigger] ?? r.trigger}</td>
                  <td>{r.violations.length === 0 ? "—" : r.violations.map((v) => GATE_REASON_LABEL[v.code] ?? v.code).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Conectar la compuerta a tu pipeline (GitHub Actions)</h2>
        <p className="empty-hint">
          Con este paso, un pull request que no pasa la compuerta (en modo Exigir) hace fallar el pipeline y no se
          puede integrar. Guarda en GitHub un secreto llamado <code>TERO_TOKEN</code> con un token de acceso de TERO (usuario
          con rol analyst o superior). Si el servidor de TERO no es accesible desde GitHub, usa un runner propio.
        </p>
        <div className="inline-form">
          <select value={repoId} onChange={(e) => setRepoId(e.target.value)}>
            {(repos.data ?? []).map((r) => (<option key={r.id} value={r.id}>{r.name}</option>))}
          </select>
          <button className="btn-secondary" onClick={copy}>{copied ? "Copiado" : "Copiar"}</button>
        </div>
        <code className="gov-code">{workflow}</code>
        <p className="empty-hint" style={{ marginBottom: 0 }}>
          Guardalo como <code>.github/workflows/tero-gobernanza.yml</code> en el repositorio. Si el repositorio no esta
          conectado en TERO, la consulta responde que no lo encuentra.
        </p>
      </div>
    </div>
  );
}
