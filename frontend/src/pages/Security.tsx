import { useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { mfaConfirm, mfaEnroll, mfaStatus, type MfaEnrollOut } from "../services/api";
import PageHeader from "../components/PageHeader";

// Seguridad de la cuenta: activar (o reemplazar) el segundo factor (MFA/TOTP).
// El servidor devuelve un QR estandar (otpauth://, RFC 6238) que sirve con Google
// Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden, etc.
// Tambien se muestra la clave en texto por si la app no puede escanear.

function detailOf(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
}

export default function Security() {
  const queryClient = useQueryClient();
  const location = useLocation();
  const justLoggedIn = (location.state as { firstLogin?: boolean } | null)?.firstLogin === true;

  const status = useQuery({ queryKey: ["mfa-status"], queryFn: mfaStatus });

  const [enrollment, setEnrollment] = useState<MfaEnrollOut | null>(null);
  const [currentCode, setCurrentCode] = useState("");
  const [newCode, setNewCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const enabled = status.data === true;

  const enroll = useMutation({
    mutationFn: async () => mfaEnroll(enabled ? currentCode.trim() : undefined),
    onSuccess: (data) => {
      setError(null);
      setDone(false);
      setNewCode("");
      setEnrollment(data);
    },
    onError: (e: unknown) => setError(detailOf(e, "No se pudo generar el codigo QR. Intenta de nuevo.")),
  });

  const confirm = useMutation({
    mutationFn: async () => mfaConfirm(newCode.trim()),
    onSuccess: () => {
      setError(null);
      setEnrollment(null);
      setCurrentCode("");
      setNewCode("");
      setDone(true);
      queryClient.invalidateQueries({ queryKey: ["mfa-status"] });
    },
    onError: (e: unknown) =>
      setError(detailOf(e, "El codigo no coincide. Revisa que la hora de tu telefono sea automatica y prueba con el codigo nuevo.")),
  });

  return (
    <div>
      <PageHeader
        title="Seguridad de la cuenta"
        subtitle="Verificacion en dos pasos (MFA) con una app de autenticacion."
      />

      {justLoggedIn && status.data === false && (
        <div className="panel">
          <p>
            Tu cuenta todavia no tiene MFA. Actívalo ahora para proteger el acceso: escaneas un QR con tu app y
            listo.
          </p>
        </div>
      )}

      <div className="panel">
        <h2>Estado</h2>
        {status.isLoading && <p className="empty-hint">Cargando...</p>}
        {status.isError && <p className="error-text">No se pudo consultar el estado del MFA.</p>}
        {status.data !== undefined && (
          <p>
            {enabled ? "MFA ACTIVO: al iniciar sesion se pide el codigo de tu app." : "MFA desactivado."}
          </p>
        )}
        {done && <p>Listo: el MFA quedo activado. Desde ahora, al iniciar sesion escribe el codigo de 6 digitos de tu app.</p>}
      </div>

      {!enrollment && status.data !== undefined && (
        <div className="panel">
          <h2>{enabled ? "Cambiar de telefono o de app" : "Activar MFA"}</h2>
          <p className="empty-hint">
            {enabled
              ? "Para reemplazar el MFA actual primero escribe un codigo vigente de tu app. Despues escanea el QR nuevo y confirma: si no confirmas, el codigo anterior deja de servir."
              : "Vas a ver un QR. Escanealo con Google Authenticator, Microsoft Authenticator, Authy, 1Password o Bitwarden."}
          </p>
          {enabled && (
            <div className="field">
              <label htmlFor="current-totp">Codigo actual de tu app</label>
              <input
                id="current-totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={currentCode}
                onChange={(e) => setCurrentCode(e.target.value)}
                placeholder="123456"
              />
            </div>
          )}
          <button
            className="btn-primary"
            onClick={() => enroll.mutate()}
            disabled={enroll.isPending || (enabled && currentCode.trim().length < 6)}
          >
            {enroll.isPending ? "Generando..." : enabled ? "Generar QR nuevo" : "Mostrar QR"}
          </button>
        </div>
      )}

      {enrollment && (
        <div className="panel">
          <h2>1. Escanea el QR</h2>
          <p className="empty-hint">Abre tu app de autenticacion, elige "agregar cuenta" y escanea este codigo.</p>
          <img
            src={enrollment.qr_code_data_uri}
            alt="QR para configurar la app de autenticacion"
            width={240}
            height={240}
            style={{ background: "#fff", padding: 8, borderRadius: 8, display: "block", margin: "12px 0" }}
          />
          <p className="empty-hint">
            Si no puedes escanear, agrega la cuenta a mano con esta clave (tipo: basado en tiempo):
          </p>
          <p>
            <code className="mono" style={{ userSelect: "all", wordBreak: "break-all" }}>{enrollment.secret}</code>
          </p>

          <h2 style={{ marginTop: 20 }}>2. Confirma con el codigo de 6 digitos</h2>
          <div className="field">
            <label htmlFor="new-totp">Codigo que muestra la app</label>
            <input
              id="new-totp"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={newCode}
              onChange={(e) => setNewCode(e.target.value)}
              placeholder="123456"
            />
          </div>
          <button className="btn-primary" onClick={() => confirm.mutate()} disabled={confirm.isPending || newCode.trim().length < 6}>
            {confirm.isPending ? "Verificando..." : "Confirmar y activar"}
          </button>
        </div>
      )}

      {error && <p className="error-text">{error}</p>}
    </div>
  );
}
