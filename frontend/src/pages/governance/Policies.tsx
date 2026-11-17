import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { coderepoApi } from "../../services/api";
import { useAuthStore } from "../../store/auth";
import { connectionErrorDetail } from "../../utils/errors";
import {
  AI_POLICY_LABEL, MODE_LABEL, POLICY_TEMPLATES, SEVERITY_LABEL, policyScopeParts, type PolicyIn, type PolicyOut,
} from "../../utils/governance";
import { t } from "../../i18n";
import type { RepoTargetOut } from "../../types";

const ADMINS = ["admin", "soc_manager"];

const EMPTY: PolicyIn = {
  name: "", repo_target_id: null, path_prefixes: "", ai_policy: "allowed", required_reviews: 0,
  block_on_severity: "high", mode: "observe", is_active: true,
};

export default function Policies() {
  const queryClient = useQueryClient();
  const claims = useAuthStore((s) => s.claims);
  const canManage = !!claims?.role && ADMINS.includes(claims.role);
  const [form, setForm] = useState<PolicyIn>(EMPTY);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const repos = useQuery({
    queryKey: ["code-repos"],
    queryFn: async () => (await coderepoApi.get<RepoTargetOut[]>("/repos")).data,
  });
  const policies = useQuery({
    queryKey: ["gov-policies"],
    queryFn: async () => (await coderepoApi.get<PolicyOut[]>("/governance/policies")).data,
  });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["gov-policies"] });
    queryClient.invalidateQueries({ queryKey: ["gov-ledger"] });
  };
  const save = useMutation({
    mutationFn: async () =>
      editingId
        ? (await coderepoApi.put<PolicyOut>(`/governance/policies/${editingId}`, form)).data
        : (await coderepoApi.post<PolicyOut>("/governance/policies", form)).data,
    onSuccess: () => { setForm(EMPTY); setEditingId(null); setError(null); refresh(); },
    onError: (e: unknown) => setError(e),
  });
  const remove = useMutation({
    mutationFn: async (id: string) => { await coderepoApi.delete(`/governance/policies/${id}`); },
    onSuccess: () => { setError(null); refresh(); },
    onError: (e: unknown) => setError(e),
  });

  const set = <K extends keyof PolicyIn>(key: K, value: PolicyIn[K]) => setForm((f) => ({ ...f, [key]: value }));
  const edit = (p: PolicyOut) => {
    setEditingId(p.id);
    setForm({
      name: p.name, repo_target_id: p.repo_target_id, path_prefixes: p.path_prefixes, ai_policy: p.ai_policy,
      required_reviews: p.required_reviews, block_on_severity: p.block_on_severity, mode: p.mode, is_active: p.is_active,
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div>
      <div className="panel">
        <h2>Politicas de uso de IA</h2>
        <p className="empty-hint">
          Defini donde se puede usar IA para escribir codigo y que control necesita cada zona. Se aplica la politica
          mas estricta de las que corresponden a los archivos de cada cambio. Sin politicas, TERO funciona en modo
          Observar con un umbral alto: <strong>mide y avisa, nunca bloquea</strong>.
        </p>
        <div className="gov-callout">
          <strong>Observar</strong> mide y marca "Hubiera bloqueado" sin frenar a nadie: empeza por aca y mira los
          numeros un tiempo. <strong>Exigir</strong> bloquea de verdad los cambios que no cumplen. Las revisiones
          exigidas cuentan solo para codigo escrito con IA.
        </div>
      </div>

      {canManage && (
        <div className="panel">
          <h2>{editingId ? "Editar politica" : "Nueva politica"}</h2>
          {!editingId && (
            <div className="gov-row-actions" style={{ marginBottom: 12 }}>
              {POLICY_TEMPLATES.map((tpl) => (
                <button key={tpl.key} className="btn-secondary" title={tpl.hint} onClick={() => setForm({ ...EMPTY, ...tpl.value })}>
                  {tpl.label}
                </button>
              ))}
            </div>
          )}
          <div className="gov-form-grid">
            <div><label>Nombre (equipo o zona)</label><input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="ej. Equipo de pagos" /></div>
            <div>
              <label>Repositorio</label>
              <select value={form.repo_target_id ?? ""} onChange={(e) => set("repo_target_id", e.target.value || null)}>
                <option value="">Todos los repositorios</option>
                {(repos.data ?? []).map((r) => (<option key={r.id} value={r.id}>{r.name}</option>))}
              </select>
            </div>
            <div><label>Zonas del codigo (carpetas, separadas por coma)</label><input value={form.path_prefixes} onChange={(e) => set("path_prefixes", e.target.value)} placeholder="vacio = todo el repositorio" /></div>
            <div>
              <label>Codigo escrito con IA</label>
              <select value={form.ai_policy} onChange={(e) => set("ai_policy", e.target.value as PolicyIn["ai_policy"])}>
                <option value="allowed">Permitido</option>
                <option value="restricted">Permitido con revision humana</option>
                <option value="forbidden">Prohibido</option>
              </select>
            </div>
            <div><label>Aprobaciones humanas exigidas (0 a 3)</label><input type="number" min={0} max={3} value={form.required_reviews} onChange={(e) => set("required_reviews", Math.min(3, Math.max(0, Number(e.target.value) || 0)))} /></div>
            <div>
              <label>Un hallazgo frena el cambio desde severidad</label>
              <select value={form.block_on_severity} onChange={(e) => set("block_on_severity", e.target.value as PolicyIn["block_on_severity"])}>
                <option value="none">Nunca</option>
                <option value="critical">Critica</option>
                <option value="high">Alta</option>
                <option value="medium">Media</option>
              </select>
            </div>
            <div>
              <label>Modo</label>
              <select value={form.mode} onChange={(e) => set("mode", e.target.value as PolicyIn["mode"])}>
                <option value="observe">Observar (solo mide y avisa)</option>
                <option value="enforce">Exigir (bloquea)</option>
              </select>
            </div>
            <div>
              <label>Estado</label>
              <select value={form.is_active ? "1" : "0"} onChange={(e) => set("is_active", e.target.value === "1")}>
                <option value="1">Activa</option>
                <option value="0">Desactivada</option>
              </select>
            </div>
          </div>
          <div className="gov-row-actions">
            <button className="btn-primary" disabled={save.isPending || !form.name.trim()} onClick={() => save.mutate()}>
              {save.isPending ? "Guardando..." : editingId ? "Guardar cambios" : "Crear politica"}
            </button>
            {editingId && <button className="btn-secondary" onClick={() => { setEditingId(null); setForm(EMPTY); }}>Cancelar</button>}
          </div>
          {error != null && <p className="error-text"><span className="error-detail">{connectionErrorDetail(error)}</span></p>}
        </div>
      )}

      <div className="panel">
        <h2>Politicas definidas</h2>
        {!canManage && (
          <p className="empty-hint">{t("Tu usuario ({0}) puede ver las politicas, pero las administra un admin o soc_manager.", claims?.role ?? "sin rol")}</p>
        )}
        {policies.isLoading && <p className="empty-hint">Cargando...</p>}
        {policies.isError && <p className="error-text"><span className="error-detail">{connectionErrorDetail(policies.error)}</span></p>}
        {policies.data && policies.data.length === 0 && <p className="empty-hint">Todavia no hay politicas: se usa el modo Observar por defecto.</p>}
        {policies.data && policies.data.length > 0 && (
          <table className="data-table">
            <thead>
              <tr><th>Nombre</th><th>Alcance</th><th>IA</th><th>Aprobaciones</th><th>Frena desde</th><th>Modo</th><th>Estado</th><th></th></tr>
            </thead>
            <tbody>
              {policies.data.map((p) => (
                <tr key={p.id}>
                  <td>{p.name}</td>
                  <td>{policyScopeParts(p).repo}{policyScopeParts(p).zones && ` · ${policyScopeParts(p).zones}`}</td>
                  <td>{AI_POLICY_LABEL[p.ai_policy]}</td>
                  <td>{p.required_reviews}</td>
                  <td>{SEVERITY_LABEL[p.block_on_severity]}</td>
                  <td><span className={p.mode === "enforce" ? "badge badge-critical" : "badge badge-neutral"}>{MODE_LABEL[p.mode]}</span></td>
                  <td>{p.is_active ? "Activa" : "Desactivada"}</td>
                  <td>
                    {canManage && (
                      <>
                        <button className="btn-link" onClick={() => edit(p)}>Editar</button>{" "}
                        <button className="btn-link" onClick={() => { if (window.confirm(t('Eliminar la politica "{0}"? Queda anotado en el registro auditable.', p.name))) remove.mutate(p.id); }}>Eliminar</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
