import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { login, loginWithGoogle } from "../services/api";
import { useAuthStore } from "../store/auth";

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;

// La libreria de Google Identity Services se carga con un <script> en
// index.html y expone window.google en runtime; no tiene tipos propios
// instalados aca, asi que se accede de forma laxa (unknown) en vez de
// agregar una dependencia npm nueva solo para esto.
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: { client_id: string; callback: (resp: { credential: string }) => void }) => void;
          renderButton: (parent: HTMLElement, options: Record<string, unknown>) => void;
        };
      };
    };
  }
}

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const setTokens = useAuthStore((s) => s.setTokens);
  const navigate = useNavigate();
  const googleButtonRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID || !googleButtonRef.current) return;

    async function handleGoogleCredential(response: { credential: string }) {
      setLoading(true);
      setError(null);
      try {
        const tokens = await loginWithGoogle(response.credential);
        setTokens(tokens.access_token, tokens.refresh_token);
        navigate("/");
      } catch {
        setError("No se pudo iniciar sesion con Google.");
      } finally {
        setLoading(false);
      }
    }

    // El script de Google puede tardar un instante en cargar; reintenta
    // un par de veces antes de rendirse en vez de asumir que ya esta listo.
    let attempts = 0;
    const tryInit = () => {
      if (window.google?.accounts?.id && googleButtonRef.current) {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCredential,
        });
        window.google.accounts.id.renderButton(googleButtonRef.current, {
          theme: "outline",
          size: "large",
          width: 280,
          text: "continue_with",
        });
      } else if (attempts < 20) {
        attempts += 1;
        setTimeout(tryInit, 250);
      }
    };
    tryInit();
  }, [navigate, setTokens]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const tokens = await login(email, password, totpCode || undefined);
      setTokens(tokens.access_token, tokens.refresh_token);
      navigate("/");
    } catch {
      setError("Credenciales invalidas o MFA requerido.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>SentinelOps</h1>
        <p>Acceso a la plataforma de seguridad</p>

        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>

        <div className="field">
          <label htmlFor="password">Contrasena</label>
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>

        <div className="field">
          <label htmlFor="totp">Codigo MFA (si esta activado)</label>
          <input id="totp" type="text" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="123456" />
        </div>

        <button className="btn-primary" type="submit" disabled={loading}>
          {loading ? "Ingresando..." : "Ingresar"}
        </button>

        {error && <p className="error-text">{error}</p>}

        {GOOGLE_CLIENT_ID && (
          <div className="google-signin-wrap">
            <div className="divider"><span>o</span></div>
            <div ref={googleButtonRef} />
          </div>
        )}
      </form>
    </div>
  );
}
