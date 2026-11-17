import { useEffect, useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import AuthShell from "../components/AuthShell";
import { forgotPassword, passwordRecoveryInfo } from "../services/api";
import { FORGOT_PASSWORD_MESSAGE } from "../utils/password";
import { connectionErrorDetail } from "../utils/errors";

// "Olvide mi contrasena" desde la pantalla de bienvenida: se pide el email y el
// servidor manda un link de un solo uso (vale 30 min). La respuesta es la misma
// exista o no la cuenta, asi que aca tampoco se puede averiguar quien tiene cuenta.
export default function ForgotPassword() {
  const location = useLocation();
  const [email, setEmail] = useState((location.state as { email?: string } | null)?.email ?? "");
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // null = todavia no se sabe (o el servidor no contesto): no se muestra ningun aviso.
  const [emailEnabled, setEmailEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    passwordRecoveryInfo()
      .then((info) => setEmailEnabled(info.email_enabled))
      .catch(() => setEmailEnabled(null));
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await forgotPassword(email.trim());
      setSent(true);
    } catch (err) {
      setError(connectionErrorDetail(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell>
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>¿Olvidaste tu contrasena?</h1>
        <p>Escribi tu email y te mandamos un link para elegir una contrasena nueva.</p>

        {emailEnabled === false && (
          <div className="empty-hint" role="note">
            <p>
              En esta instalacion el envio de mails no esta configurado, asi que no te va a llegar ningun link. Pedile
              a un administrador que te genere uno desde Usuarios y roles (Restablecer contrasena).
            </p>
            <p>
              Si administras el servidor, podes generarlo desde la carpeta de TERO Security con este comando:
            </p>
            <p>
              <code className="mono" style={{ userSelect: "all", wordBreak: "break-all" }}>
                docker compose exec auth-service python -m app.cli_password tu@email.com
              </code>
            </p>
          </div>
        )}

        {sent ? (
          <>
            <p className="empty-hint">{FORGOT_PASSWORD_MESSAGE}</p>
            <p className="empty-hint">
              El link vale 30 minutos y se puede usar una sola vez. Si en esta instalacion no esta configurado el
              envio de mails, pedile a un administrador que te genere el link desde Usuarios y roles.
            </p>
          </>
        ) : (
          <>
            <div className="field">
              <label htmlFor="forgot-email">Email</label>
              <input
                id="forgot-email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <button className="btn-primary" type="submit" disabled={loading || !email.trim()}>
              {loading ? "Enviando..." : "Enviarme el link"}
            </button>
            {error && <p className="error-text">{error}</p>}
          </>
        )}

        <p className="empty-hint" style={{ marginTop: 12 }}>
          <Link to="/login">Volver a ingresar</Link>
        </p>
      </form>
    </AuthShell>
  );
}
