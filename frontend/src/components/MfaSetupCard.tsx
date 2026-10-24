import { useState, type FormEvent } from "react";
import { mfaConfirm, type MfaEnrollOut } from "../services/api";
import { groupSecret, normalizeTotp, totpProblem } from "../utils/mfaSetup";

function detailOf(error: unknown): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string"
    ? detail
    : "El codigo no coincide. Revisa que la hora de tu telefono sea automatica y proba con el codigo nuevo.";
}

// Paso que aparece justo despues de crear la cuenta: se muestra el QR del MFA y, al confirmar con
// el codigo de 6 digitos de la app, la cuenta queda vinculada y se entra a TERO Security. Desde
// ese momento el login pide ese codigo. Se puede omitir (se activa despues en Seguridad de la cuenta).
export default function MfaSetupCard({
  enrollment,
  onDone,
  onSkip,
}: {
  enrollment: MfaEnrollOut;
  onDone: () => void;
  onSkip: () => void;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const problem = totpProblem(code);
    if (problem) {
      setError(problem);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await mfaConfirm(normalizeTotp(code));
      onDone();
    } catch (err) {
      setError(detailOf(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="login-card" onSubmit={handleSubmit}>
      <h1>Vincula tu MFA</h1>
      <p>Tu cuenta ya esta creada. Un ultimo paso para proteger el acceso: escanea el QR con tu app de autenticacion.</p>

      <p className="empty-hint">
        1) Abri Google Authenticator, Microsoft Authenticator, Authy, 1Password o Bitwarden y elegi "agregar cuenta".
        2) Escanea este QR. 3) Escribi abajo el codigo de 6 digitos que muestra la app.
      </p>
      <img
        src={enrollment.qr_code_data_uri}
        alt="QR para configurar la app de autenticacion"
        width={220}
        height={220}
        style={{ background: "#fff", padding: 8, borderRadius: 8, display: "block", margin: "12px auto" }}
      />
      <p className="empty-hint">Si no podes escanear, agrega la cuenta a mano con esta clave (tipo: basado en tiempo):</p>
      <p>
        <code className="mono" style={{ userSelect: "all", wordBreak: "break-all" }}>
          {groupSecret(enrollment.secret)}
        </code>
      </p>

      <div className="field">
        <label htmlFor="setup-totp">Codigo de 6 digitos de tu app</label>
        <input
          id="setup-totp"
          inputMode="numeric"
          autoComplete="one-time-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="123456"
          autoFocus
        />
      </div>
      <button className="btn-primary" type="submit" disabled={loading || !code.trim()}>
        {loading ? "Verificando..." : "Confirmar y entrar"}
      </button>
      {error && <p className="error-text">{error}</p>}

      <p className="empty-hint" style={{ marginTop: 12 }}>
        <button type="button" className="btn-link" onClick={onSkip}>
          Omitir por ahora
        </button>{" "}
        (lo podes activar despues en Seguridad de la cuenta; mientras no lo actives, el login no pide codigo).
      </p>
    </form>
  );
}
