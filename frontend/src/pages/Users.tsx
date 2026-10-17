import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { authApi, type MfaEnrollOut } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { AssignableRole, OrganizationOut, UserAdminOut } from "../types";
import PageHeader from "../components/PageHeader";
import { connectionErrorDetail } from "../utils/errors";

// Usuarios y roles de la organizacion. Es la UNICA via donde se elige el rol de
// una cuenta nueva: la hace un administrador. Quien se registra solo (email o
// Google sin alta previa) entra como "Solo lectura" y nunca elige su propio rol.
//
// Jerarquia:
//   Administrador  -> todo, incluida la administracion de usuarios, SSO y pagos
//   Gerente SOC    -> opera todo el SOC (escaneos, casos, SOAR, reportes)
//   Analista       -> ejecuta tareas operativas (escaneos, triage, casos)
//   Solo lectura   -> ve el sistema, no ejecuta ni modifica nada
const ROLES: { value: AssignableRole; label: string; help: string }[] = [
  { value: "admin", label: "Administrador", help: "Acceso total: ejecuta todo y administra usuarios, SSO y pagos." },
  { value: "soc_manager", label: "Gerente SOC", help: "Opera todo el SOC: escaneos, casos, SOAR y reportes." },
  { value: "analyst", label: "Analista", help: "Ejecuta tareas operativas: escaneos, triage y casos." },
  { value: "viewer", label: "Solo lectura", help: "Ve el sistema sin poder ejecutar ni modificar nada." },
];
const roleLabel = (r: string) => ROLES.find((x) => x.value === r)?.label ?? r;

export default function Users() {
  const claims = useAuthStore((s) => s.claims);
  const isPlatformAdmin = claims?.platform_admin === true;
  const ownOrgId = typeof claims?.org_id === "string" ? claims.org_id : null;
  const myId = typeof claims?.sub === "string" ? claims.sub : "";
  const queryClient = useQueryClient();

  const [selectedOrgId, setSelectedOrgId] = useState("");
  const orgId = isPlatformAdmin ? selectedOrgId : ownOrgId ?? "";

  const organizations = useQuery({
    queryKey: ["organizations"],
    queryFn: async () => (await authApi.get<OrganizationOut[]>("/auth/organizations")).data,
    enabled: isPlatformAdmin,
  });

  const users = useQuery({
    queryKey: ["org-users", orgId],
    queryFn: async () => (await authApi.get<UserAdminOut[]>(`/auth/organizations/${orgId}/users`)).data,
    enabled: !!orgId,
  });

  // --- Alta ---
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [role, setRole] = useState<AssignableRole>("viewer");
  const [access, setAccess] = useState<"local" | "google">("local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<string | null>(null);
  const [linkMfa, setLinkMfa] = useState(true);

  // Vinculacion de MFA hecha por el admin: QR de la cuenta de OTRA persona. El MFA
  // queda activo recien cuando se confirma con el codigo de 6 digitos de la app.
  const [linking, setLinking] = useState<{ userId: string; email: string; qr: MfaEnrollOut } | null>(null);
  const [linkCode, setLinkCode] = useState("");
  const [linkDone, setLinkDone] = useState<string | null>(null);

  const startLink = useMutation({
    mutationFn: async (v: { userId: string; email: string }) => {
      const qr = (await authApi.post<MfaEnrollOut>(`/auth/organizations/${orgId}/users/${v.userId}/mfa`)).data;
      return { ...v, qr };
    },
    onSuccess: (r) => {
      setError(null);
      setLinkDone(null);
      setLinkCode("");
      setLinking({ userId: r.userId, email: r.email, qr: r.qr });
      queryClient.invalidateQueries({ queryKey: ["org-users", orgId] });
    },
    onError: (e: unknown) => setError(connectionErrorDetail(e)),
  });

  const confirmLink = useMutation({
    mutationFn: async () =>
      (
        await authApi.post<UserAdminOut>(`/auth/organizations/${orgId}/users/${linking?.userId}/mfa/confirm`, {
          totp_code: linkCode.trim(),
        })
      ).data,
    onSuccess: (u) => {
      setError(null);
      setLinkDone(`Listo: el MFA de ${u.email} quedo vinculado y activo. Desde ahora le pide el codigo al entrar.`);
      setLinking(null);
      setLinkCode("");
      queryClient.invalidateQueries({ queryKey: ["org-users", orgId] });
    },
    onError: (e: unknown) => setError(connectionErrorDetail(e)),
  });

  const createUser = useMutation({
    mutationFn: async () =>
      (
        await authApi.post<UserAdminOut>(`/auth/organizations/${orgId}/users`, {
          email: email.trim(),
          full_name: fullName.trim(),
          role,
          password: access === "local" ? password : null,
        })
      ).data,
    onSuccess: (u) => {
      setError(null);
      setLinkDone(null);
      setCreated(
        u.auth_provider === "google"
          ? `Listo: ${u.email} ya puede entrar con Google (rol: ${roleLabel(u.role_name)}).`
          : linkMfa
            ? `Cuenta creada para ${u.email} (rol: ${roleLabel(u.role_name)}). Ahora vincula su MFA con el QR de abajo.`
            : `Listo: cuenta creada para ${u.email} (rol: ${roleLabel(u.role_name)}). Pasale la contrasena; puede activar el MFA desde Seguridad de la cuenta.`,
      );
      setEmail("");
      setFullName("");
      setPassword("");
      queryClient.invalidateQueries({ queryKey: ["org-users", orgId] });
      if (u.auth_provider === "local" && linkMfa) startLink.mutate({ userId: u.id, email: u.email });
    },
    onError: (e: unknown) => {
      setCreated(null);
      setError(connectionErrorDetail(e));
    },
  });

  // --- Cambios (rol / activar-desactivar) ---
  const updateUser = useMutation({
    mutationFn: async (v: { id: string; role?: string; is_active?: boolean }) =>
      (await authApi.patch<UserAdminOut>(`/auth/organizations/${orgId}/users/${v.id}`, { role: v.role, is_active: v.is_active })).data,
    onSuccess: () => {
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["org-users", orgId] });
    },
    onError: (e: unknown) => setError(connectionErrorDetail(e)),
  });

  const passwordTooShort = access === "local" && password.length < 12;

  return (
    <div>
      <PageHeader
        title="Usuarios y roles"
        subtitle="Crea cuentas y define quien administra todo y quien solo puede ver."
      />

      {isPlatformAdmin && (
        <div className="panel">
          <h2>Elegir organizacion</h2>
          <select value={selectedOrgId} onChange={(e) => setSelectedOrgId(e.target.value)}>
            <option value="">-- elegi una --</option>
            {(organizations.data ?? []).map((o) => (
              <option key={o.id} value={o.id}>{o.name}</option>
            ))}
          </select>
        </div>
      )}

      {orgId && (
        <>
          <div className="panel">
            <h2>Crear cuenta</h2>
            <p className="empty-hint">
              El rol lo eliges tu. Quien se registra por su cuenta (sin que lo des de alta aca) entra como
              <strong> Solo lectura</strong> y no puede elegir su rol.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                createUser.mutate();
              }}
            >
              <div className="field">
                <label htmlFor="u-email">Email</label>
                <input id="u-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
              </div>
              <div className="field">
                <label htmlFor="u-name">Nombre (opcional)</label>
                <input id="u-name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor="u-role">Rol</label>
                <select id="u-role" value={role} onChange={(e) => setRole(e.target.value as AssignableRole)}>
                  {ROLES.map((r) => (
                    <option key={r.value} value={r.value}>{r.label}</option>
                  ))}
                </select>
                <p className="empty-hint">{ROLES.find((r) => r.value === role)?.help}</p>
              </div>
              <div className="field">
                <label htmlFor="u-access">Como va a entrar</label>
                <select id="u-access" value={access} onChange={(e) => setAccess(e.target.value as "local" | "google")}>
                  <option value="local">Email y contrasena (puede activar MFA con QR)</option>
                  <option value="google">Con Google (usa el email de arriba)</option>
                </select>
              </div>
              {access === "local" && (
                <div className="field">
                  <label htmlFor="u-pass">Contrasena inicial (minimo 12 caracteres)</label>
                  <input
                    id="u-pass"
                    type="password"
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    minLength={12}
                    required
                  />
                </div>
              )}
              {access === "local" && (
                <div className="field">
                  <label>
                    <input type="checkbox" checked={linkMfa} onChange={(e) => setLinkMfa(e.target.checked)} />{" "}
                    Vincular el MFA ahora (muestra el QR para escanear con la app de la persona)
                  </label>
                </div>
              )}
              <button className="btn-primary" type="submit" disabled={createUser.isPending || !email || passwordTooShort}>
                {createUser.isPending ? "Creando..." : "Crear cuenta"}
              </button>
            </form>
            {created && <p>{created}</p>}
          </div>

          {linking && (
            <div className="panel">
              <h2>Vincular MFA de {linking.email}</h2>
              <p className="empty-hint">
                1) Con el telefono de esa persona (Google Authenticator, Microsoft Authenticator, Authy, 1Password o
                Bitwarden) escanea este QR. 2) Escribi abajo el codigo de 6 digitos que muestra la app. El MFA se activa
                recien cuando el codigo es correcto. Este QR se muestra una sola vez: no lo captures ni lo envies por chat.
              </p>
              <img
                src={linking.qr.qr_code_data_uri}
                alt="QR para vincular el MFA"
                width={240}
                height={240}
                style={{ background: "#fff", padding: 8, borderRadius: 8, display: "block", margin: "12px 0" }}
              />
              <p className="empty-hint">Si no puede escanear, clave manual (tipo: basado en tiempo):</p>
              <p>
                <code className="mono" style={{ userSelect: "all", wordBreak: "break-all" }}>{linking.qr.secret}</code>
              </p>
              <div className="field">
                <label htmlFor="link-code">Codigo de 6 digitos de la app</label>
                <input
                  id="link-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={linkCode}
                  onChange={(e) => setLinkCode(e.target.value)}
                  placeholder="123456"
                />
              </div>
              <button
                className="btn-primary"
                onClick={() => confirmLink.mutate()}
                disabled={confirmLink.isPending || linkCode.trim().length < 6}
              >
                {confirmLink.isPending ? "Verificando..." : "Confirmar y activar MFA"}
              </button>{" "}
              <button className="btn-secondary" onClick={() => setLinking(null)}>Cerrar (queda sin MFA)</button>
            </div>
          )}
          {linkDone && <div className="panel"><p>{linkDone}</p></div>}

          <div className="panel">
            <h2>Cuentas de la organizacion</h2>
            {users.isLoading && <p className="empty-hint">Cargando...</p>}
            {users.isError && <p className="error-text">{connectionErrorDetail(users.error)}</p>}
            {users.data && (
              <table>
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Rol</th>
                    <th>Acceso</th>
                    <th>MFA</th>
                    <th>Estado</th>
                  </tr>
                </thead>
                <tbody>
                  {users.data.map((u) => {
                    const isMe = u.id === myId;
                    return (
                      <tr key={u.id}>
                        <td>
                          {u.email}
                          {isMe && " (vos)"}
                          {u.full_name && <div className="empty-hint">{u.full_name}</div>}
                        </td>
                        <td>
                          <select
                            value={u.role_name}
                            disabled={isMe || updateUser.isPending}
                            title={isMe ? "No podes cambiar tu propio rol" : undefined}
                            onChange={(e) => updateUser.mutate({ id: u.id, role: e.target.value })}
                          >
                            {ROLES.map((r) => (
                              <option key={r.value} value={r.value}>{r.label}</option>
                            ))}
                          </select>
                        </td>
                        <td>{u.auth_provider === "google" ? "Google" : "Email y contrasena"}</td>
                        <td>
                          {u.mfa_enabled ? "Activo" : "No"}
                          {u.auth_provider === "local" && !isMe && (
                            <>
                              {" "}
                              <button
                                className="btn-secondary"
                                disabled={startLink.isPending}
                                onClick={() => startLink.mutate({ userId: u.id, email: u.email })}
                              >
                                {u.mfa_enabled ? "Reemplazar MFA" : "Vincular MFA"}
                              </button>
                            </>
                          )}
                        </td>
                        <td>
                          <button
                            className="btn-secondary"
                            disabled={isMe || updateUser.isPending}
                            onClick={() => updateUser.mutate({ id: u.id, is_active: !u.is_active })}
                          >
                            {u.is_active ? "Desactivar" : "Activar"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {error && <p className="error-text">{error}</p>}
    </div>
  );
}
