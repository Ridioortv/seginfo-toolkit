import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import PageHeader from "../components/PageHeader";
import { authApi, caseApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import { connectionErrorDetail } from "../utils/errors";
import { saveBlob } from "../utils/download";
import { fmtMsg, PERIODS } from "../utils/executive";
import { checkLogoFile, validColor, type Brand } from "../utils/brand";
import { CLIENT_STATUS_BADGE, CLIENT_STATUS_LABEL, canEnter, expiryNote, figure, type PartnerOverview } from "../utils/partner";
import { currentLocale, t } from "../i18n";

function errorText(err: unknown): string {
  if (isAxiosError(err)) {
    const d = err.response?.data?.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d) && d[0]?.msg) return String(d[0].msg);
  }
  return connectionErrorDetail(err);
}

function Tile({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="stat-card">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {hint && <span className="empty-hint">{hint}</span>}
    </div>
  );
}

/** Consola del partner (MSSP): todos sus clientes en una pantalla, con acceso a cada uno y marca propia. */
export default function Partner() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const enterClient = useAuthStore((s) => s.enterClient);
  const isAdmin = role === "admin";
  const canExport = role === "admin" || role === "soc_manager";
  const [days, setDays] = useState(30);

  const overview = useQuery({
    queryKey: ["partner-overview", days], refetchInterval: 2 * 60_000,
    queryFn: async () => (await caseApi.get<PartnerOverview>("/partner/overview", { params: { days } })).data,
  });

  const enter = useMutation({
    mutationFn: async (id: string) => (await authApi.post<{ access_token: string }>(`/auth/partner/clients/${id}/enter`)).data,
    onSuccess: (d) => {
      enterClient(d.access_token);
      queryClient.clear(); // lo que estaba en memoria es de la organizacion del partner: no se mezcla con el cliente
      navigate("/");
    },
  });
  const setActive = useMutation({
    mutationFn: async (v: { id: string; active: boolean }) => (await authApi.patch(`/auth/partner/clients/${v.id}`, { is_active: v.active })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["partner-overview"] }),
  });
  const csv = useMutation({
    mutationFn: async () => saveBlob(await caseApi.get<Blob>("/partner/usage.csv", { params: { days }, responseType: "blob" }), "uso-por-cliente.csv"),
  });

  // --- alta de cliente ---
  const [name, setName] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [adminName, setAdminName] = useState("");
  const [adminPass, setAdminPass] = useState("");
  const [withAdmin, setWithAdmin] = useState(false);
  const create = useMutation({
    mutationFn: async () => (await authApi.post("/auth/partner/clients", {
      name: name.trim(), ...(withAdmin ? { admin_email: adminEmail.trim(), admin_full_name: adminName.trim(), admin_password: adminPass } : {}),
    })).data,
    onSuccess: () => {
      setName(""); setAdminEmail(""); setAdminName(""); setAdminPass(""); setWithAdmin(false);
      queryClient.invalidateQueries({ queryKey: ["partner-overview"] });
    },
  });
  function submitClient(e: FormEvent) { e.preventDefault(); create.mutate(); }

  const d = overview.data;
  const tt = d?.totals;
  return (
    <div>
      <PageHeader title="Consola de clientes" subtitle="Todos tus clientes en una pantalla: quien necesita atencion primero, y acceso directo a cada uno" />
      {overview.isError && <div className="panel"><p className="error-text"><span className="error-detail">{errorText(overview.error)}</span></p></div>}
      {overview.isLoading && <div className="panel"><p className="empty-hint">{t("Cargando...")}</p></div>}
      {d && tt && (
        <>
          <div className="panel">
            <div className="gov-row-actions" style={{ marginTop: 0, alignItems: "center", flexWrap: "wrap" }}>
              <label className="empty-hint">{t("Periodo")}{" "}
                <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label={t("Periodo")}>
                  {PERIODS.map((p) => <option key={p} value={p}>{t("Ultimos {0} dias", p)}</option>)}
                </select>
              </label>
              <span className="empty-hint">{t("Actualizado: {0}", new Date(d.generated_at).toLocaleTimeString(currentLocale()))}</span>
              {canExport && (
                <button className="btn-secondary" disabled={csv.isPending} onClick={() => csv.mutate()}>
                  {csv.isPending ? t("Preparando...") : t("Descargar uso por cliente (CSV)")}
                </button>
              )}
            </div>
            {csv.isError && <p className="error-text"><span className="error-detail">{errorText(csv.error)}</span></p>}
          </div>

          <div className="cards-grid">
            <Tile label={t("Clientes")} value={tt.clients} hint={t("Activos: {0}", tt.active)} />
            <Tile label={t("Requieren atencion")} value={tt.by_status.attention} hint={t("{0} a vigilar", tt.by_status.watch)} />
            <Tile label={t("Criticas y altas abiertas")} value={tt.critical_high} hint={t("{0} explotadas activamente", tt.kev)} />
            <Tile label={t("Casos vencidos")} value={tt.cases_overdue} hint={t("{0} casos abiertos", tt.cases_open)} />
            <Tile label={t("Activos protegidos")} value={tt.assets} hint={t("Usuarios: {0}", tt.users)} />
          </div>
          {tt.by_status.unknown > 0 && (
            <div className="panel"><p className="error-text"><span className="error-detail">{t("No se pudieron leer {0} clientes: aparecen como \"Sin datos\" y no suman a los totales.", tt.by_status.unknown)}</span></p></div>
          )}

          <div className="panel">
            <h3>{t("Clientes")}</h3>
            {d.clients.length === 0 && <p className="empty-hint">{t("Todavia no tenes clientes. Crea el primero abajo.")}</p>}
            {d.clients.length > 0 && (
              <div style={{ overflowX: "auto" }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>{t("Cliente")}</th><th>{t("Estado")}</th><th>{t("Criticas y altas")}</th><th>{t("Explotadas")}</th>
                      <th>{t("Casos vencidos")}</th><th>{t("Activos")}</th><th>{t("Suscripcion")}</th><th>{t("Que mirar")}</th><th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.clients.map((c) => {
                      const ex = expiryNote(c.subscription_expires_at);
                      return (
                        <tr key={c.id}>
                          <td style={{ minWidth: 150 }}><strong>{c.name}</strong><div className="empty-hint">{t("Usuarios: {0}", c.users)}</div></td>
                          <td>
                            <span className={CLIENT_STATUS_BADGE[c.status]}>{t(CLIENT_STATUS_LABEL[c.status])}</span>
                            {c.status === "unknown" && <div className="empty-hint">{t("No se pudo leer")}{c.error ? ` (${c.error})` : ""}</div>}
                          </td>
                          <td>{figure(c.critical_high)}</td>
                          <td>{figure(c.kev)}</td>
                          <td>{figure(c.cases_overdue)}</td>
                          <td>{figure(c.assets)}</td>
                          <td>
                            {ex.key === "expired" ? <span className="badge badge-critical">{t("Vencida")}</span>
                              : ex.key === "soon" ? <span className="badge badge-high">{t("Vence en {0} dias", ex.days)}</span>
                              : ex.key === "ok" ? <span className="empty-hint">{t("Vence en {0} dias", ex.days)}</span> : "-"}
                          </td>
                          <td style={{ minWidth: 220, maxWidth: 340 }}>
                            {(c.top_attention ?? []).map((a) => <div key={a.code} className="empty-hint">- {fmtMsg(a.message)}</div>)}
                            {c.status === "stable" && (c.top_attention ?? []).length === 0 && <span className="empty-hint">{t("Sin alertas")}</span>}
                          </td>
                          <td>
                            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 6 }}>
                            <button className="btn-primary" disabled={!canEnter(c) || enter.isPending} onClick={() => enter.mutate(c.id)}>
                              {t("Entrar")}
                            </button>
                            {isAdmin && (
                              <button className="btn-link" disabled={setActive.isPending}
                                onClick={() => setActive.mutate({ id: c.id, active: !c.is_active })}>
                                {c.is_active ? t("Suspender") : t("Reactivar")}
                              </button>
                            )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {enter.isError && <p className="error-text"><span className="error-detail">{errorText(enter.error)}</span></p>}
            {setActive.isError && <p className="error-text"><span className="error-detail">{errorText(setActive.error)}</span></p>}
            <p className="empty-hint">{t("Al entrar trabajas dentro de ese cliente con permisos de gestion (no de administracion) durante una hora. Cada ingreso queda registrado y el cliente lo ve en su cadena de custodia.")}</p>
          </div>
        </>
      )}

      {isAdmin && (
        <div className="panel">
          <h3>{t("Nuevo cliente")}</h3>
          <form onSubmit={submitClient}>
            <div className="field">
              <label htmlFor="pc-name">{t("Nombre del cliente")}</label>
              <input id="pc-name" value={name} minLength={2} maxLength={100} required onChange={(e) => setName(e.target.value)} />
            </div>
            <label className="gov-row-check">
              <input type="checkbox" checked={withAdmin} onChange={(e) => setWithAdmin(e.target.checked)} /> {t("Crear tambien un usuario administrador para la gente del cliente")}
            </label>
            {withAdmin && (
              <div className="inline-form" style={{ marginTop: 8 }}>
                <input type="email" placeholder={t("Email")} value={adminEmail} required onChange={(e) => setAdminEmail(e.target.value)} aria-label={t("Email")} />
                <input placeholder={t("Nombre y apellido")} value={adminName} onChange={(e) => setAdminName(e.target.value)} aria-label={t("Nombre y apellido")} />
                <input type="password" placeholder={t("Contrasena (12 caracteres o mas)")} value={adminPass} minLength={12} required
                  onChange={(e) => setAdminPass(e.target.value)} aria-label={t("Contrasena")} autoComplete="new-password" />
              </div>
            )}
            <div style={{ marginTop: 10 }}>
              <button className="btn-primary" type="submit" disabled={create.isPending || name.trim().length < 2}>
                {create.isPending ? t("Creando...") : t("Crear cliente")}
              </button>
            </div>
            {create.isError && <p className="error-text"><span className="error-detail">{errorText(create.error)}</span></p>}
          </form>
        </div>
      )}

      {isAdmin && <BrandPanel />}
    </div>
  );
}

function BrandPanel() {
  const queryClient = useQueryClient();
  const current = useQuery({ queryKey: ["brand"], queryFn: async () => (await authApi.get<Brand>("/auth/brand")).data });
  const [name, setName] = useState("");
  const [color, setColor] = useState("");
  const [logo, setLogo] = useState("");
  const [fileError, setFileError] = useState("");
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    if (current.data && !loaded) {
      setName(current.data.name); setColor(current.data.color); setLogo(current.data.logo); setLoaded(true);
    }
  }, [current.data, loaded]);

  const save = useMutation({
    mutationFn: async () => (await authApi.put("/auth/partner/brand", { name: name.trim(), color: color.trim(), logo })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["brand"] }),
  });

  function pick(file: File | undefined) {
    setFileError("");
    if (!file) return;
    const check = checkLogoFile(file);
    if (!check.ok) { setFileError(check.reason); return; }
    const reader = new FileReader();
    reader.onload = () => setLogo(String(reader.result));
    reader.readAsDataURL(file);
  }

  const colorOk = color === "" || validColor(color);
  return (
    <div className="panel">
      <h3>{t("Marca propia")}</h3>
      <p className="empty-hint">{t("Tu nombre, logo y color reemplazan a los de TERO en la pantalla y en los informes de tus clientes (si un cliente no tiene marca propia, usa la tuya).")}</p>
      <div className="inline-form">
        <input placeholder={t("Nombre de tu marca")} value={name} maxLength={60} onChange={(e) => setName(e.target.value)} aria-label={t("Nombre de tu marca")} />
        <label className="empty-hint">{t("Color")}{" "}
          <input type="color" value={validColor(color) ? color : "#4f46e5"} onChange={(e) => setColor(e.target.value)} aria-label={t("Color de la marca")} />
        </label>
        <input placeholder="#4f46e5" value={color} maxLength={7} onChange={(e) => setColor(e.target.value)} aria-label={t("Color en formato #RRGGBB")} style={{ maxWidth: 110 }} />
      </div>
      <div style={{ marginTop: 10 }}>
        <label className="empty-hint">{t("Logo (PNG o JPEG, hasta 150 KB)")}{" "}
          <input type="file" accept="image/png,image/jpeg" onChange={(e) => pick(e.target.files?.[0])} aria-label={t("Logo")} />
        </label>
        {logo && (
          <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 12 }}>
            <img src={logo} alt={t("Vista previa del logo")} style={{ maxHeight: 48, maxWidth: 200 }} />
            <button type="button" className="btn-link" onClick={() => setLogo("")}>{t("Quitar logo")}</button>
          </div>
        )}
        {fileError && <p className="error-text"><span className="error-detail">{t(fileError)}</span></p>}
      </div>
      <div style={{ marginTop: 10 }}>
        <button className="btn-primary" disabled={save.isPending || !colorOk} onClick={() => save.mutate()}>
          {save.isPending ? t("Guardando...") : t("Guardar marca")}
        </button>
        {!colorOk && <span className="error-text"> <span className="error-detail">{t("El color tiene que ser del tipo #1a73e8")}</span></span>}
        {save.isSuccess && <span className="empty-hint"> {t("Guardado.")}</span>}
      </div>
      {save.isError && <p className="error-text"><span className="error-detail">{errorText(save.error)}</span></p>}
    </div>
  );
}
